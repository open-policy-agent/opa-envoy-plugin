#!/bin/bash
# Envoy initialization script responsible for setting up port forwarding.

set -o errexit
set -o nounset
set -o pipefail

usage() {
  echo "${0} -p INBOUND_PORT -o OUTBOUND_PORT -u UID [-h]"
  echo ''
  echo '  -p: Specify the envoy port to which redirect all inbound TCP traffic'
  echo '  -o: Specify the envoy port to which redirect all outbound TCP traffic'
  echo '  -u: Specify the UID of the user for which the redirection is not'
  echo '      applied. Typically, this is the UID of the proxy container'
  echo '  -i: Comma separated list of IP ranges in CIDR form to redirect to envoy (optional)'
  echo '  -w: Comma separated list of ports to allow inbound TCP traffic without redirecting to envoy (optional)'
  echo ''
}

IP_RANGES_INCLUDE=""
WHITELIST_PORTS=""

while getopts ":p:o:u:e:i:w:h" opt; do
  case ${opt} in
    p)
      ENVOY_IN_PORT=${OPTARG}
      ;;
    o)
      ENVOY_OUT_PORT=${OPTARG}
      ;;
    u)
      ENVOY_UID=${OPTARG}
      ;;
    i)
      IP_RANGES_INCLUDE=${OPTARG}
      ;;
    w)
      WHITELIST_PORTS=${OPTARG}
      ;;
    h)
      usage
      exit 0
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${ENVOY_IN_PORT-}" ]] || [[ -z "${ENVOY_UID-}" ]]; then
  echo "Please set both -p and -u parameters"
  usage
  exit 1
fi

# Create a new chain for redirecting inbound traffic to Envoy port
iptables -t nat -N ENVOY_IN_REDIRECT                                                    -m comment --comment "envoy/redirect-inbound-chain"

# Skip Envoy for whitelisted ports
if [[ WHITELIST_PORTS != "" ]]; then
  IFS=,
  for port in ${WHITELIST_PORTS}; do
    iptables -t nat -A ENVOY_IN_REDIRECT -p tcp --dport ${port} -m conntrack --ctstate NEW,ESTABLISHED -j RETURN  -m comment --comment "envoy/whitelisted-port-ingress"
  done
fi

iptables -t nat -A ENVOY_IN_REDIRECT -p tcp -j REDIRECT --to-port ${ENVOY_IN_PORT}      -m comment --comment "envoy/redirect-to-envoy-inbound-port"

# Redirect all inbound traffic to Envoy.
iptables -t nat -A PREROUTING -p tcp -j ENVOY_IN_REDIRECT                               -m comment --comment "envoy/install-envoy-inbound-prerouting"

if [[ ! -z "${ENVOY_OUT_PORT-}" ]]; then
    # Create a new chain for selectively redirecting outbound packets to Envoy port
    iptables -t nat -N ENVOY_OUT_REDIRECT                                               -m comment --comment "envoy/redirect-outbound-chain"

    # Jump to the ENVOY_OUT_REDIRECT chain from OUTPUT chain for all tcp traffic.
    # '-j RETURN' bypasses Envoy and '-j ENVOY_OUT_REDIRECT' redirects to Envoy.
    iptables -t nat -A OUTPUT -p tcp -j ENVOY_OUT_REDIRECT                              -m comment --comment "envoy/install-envoy-out-redirect"

    # Redirect app calls back to itself via Envoy when using the service VIP or
    # endpoint address, e.g. appN => Envoy (client) => Envoy (server) => appN.
    iptables -t nat -A ENVOY_OUT_REDIRECT -o lo ! -d 127.0.0.1/32 -j ENVOY_IN_REDIRECT  -m comment --comment "envoy/redirect-implicit-loopback"

    # Avoid infinite loops. Don't redirect Envoy traffic directly back to Envoy for
    # non-loopback traffic.
    iptables -t nat -A ENVOY_OUT_REDIRECT -m owner --uid-owner ${ENVOY_UID} -j RETURN   -m comment --comment "envoy/outbound-bypass-envoy"

    # Skip redirection for Envoy-aware applications and container-to-container
    # traffic both of which explicitly use localhost.
    iptables -t nat -A ENVOY_OUT_REDIRECT -d 127.0.0.1/32 -j RETURN                     -m comment --comment "envoy/bypass-explicit-loopback"

    # All outbound traffic will be redirected to Envoy by default. If
    # IP_RANGES_INCLUDE is non-empty, only traffic bound for the destinations
    # specified in this list will be captured.
    IFS=,
    if [ "${IP_RANGES_INCLUDE}" != "" ]; then
        for cidr in ${IP_RANGES_INCLUDE}; do
            iptables -t nat -A ENVOY_OUT_REDIRECT -d ${cidr} -p tcp -j REDIRECT --to-port ${ENVOY_OUT_PORT}    -m comment --comment "envoy/redirect-ip-range-${cidr}"
        done
        iptables -t nat -A ENVOY_OUT_REDIRECT -p tcp -j RETURN                                                 -m comment --comment "envoy/bypass-default-outbound"
    else
        iptables -t nat -A ENVOY_OUT_REDIRECT -p tcp -j REDIRECT --to-port ${ENVOY_OUT_PORT}                   -m comment --comment "envoy/redirect-default-outbound"
        #iptables -t nat -A ENVOY_OUT_REDIRECT -p tcp -j RETURN                                                 -m comment --comment "envoy/bypass-default-outbound"
    fi
fi

exit 0
