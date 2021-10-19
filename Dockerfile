# Copyright 2018 The OPA Authors. All rights reserved.
# Use of this source code is governed by an Apache2
# license that can be found in the LICENSE file.

ARG BASE

FROM ${BASE}

MAINTAINER Ashutosh Narkar  <anarkar4387@gmail.com>

WORKDIR /app

COPY opa_envoy_linux_GOARCH /app

ENTRYPOINT ["./opa_envoy_linux_GOARCH"]

CMD ["run"]
