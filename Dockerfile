# Copyright 2018 The OPA Authors. All rights reserved.
# Use of this source code is governed by an Apache2
# license that can be found in the LICENSE file.

ARG BASE

FROM ${BASE}

# Any non-zero number will do, and unfortunately a named user will not, as k8s
# pod securityContext runAsNonRoot can't resolve the user ID:
# https://github.com/kubernetes/kubernetes/issues/40958.
ARG USER=1000:1000
USER ${USER}

MAINTAINER Ashutosh Narkar  <anarkar4387@gmail.com>

WORKDIR /app

COPY opa_envoy_linux_GOARCH /app

ENTRYPOINT ["./opa_envoy_linux_GOARCH"]

CMD ["run"]
