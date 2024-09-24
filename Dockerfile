# Copyright 2018 The OPA Authors. All rights reserved.
# Use of this source code is governed by an Apache2
# license that can be found in the LICENSE file.

ARG BASE

FROM ${BASE}

LABEL org.opencontainers.image.authors="Ashutosh Narkar <anrkar4387@gmail.com>"

# Any non-zero number will do, and unfortunately a named user will not, as k8s
# pod securityContext runAsNonRoot can't resolve the user ID:
# https://github.com/kubernetes/kubernetes/issues/40958.
ARG USER=1000:1000
USER ${USER}

# TARGETOS and TARGETARCH are automatic platform args injected by BuildKit
# https://docs.docker.com/engine/reference/builder/#automatic-platform-args-in-the-global-scope
ARG TARGETOS
ARG TARGETARCH
# VARIANT is used to specify the build variant of the image, e.g. static or dynamic
ARG VARIANT

COPY opa_envoy_${TARGETOS}_${TARGETARCH}_${VARIANT} /opa

ENTRYPOINT ["/opa"]

CMD ["run"]
