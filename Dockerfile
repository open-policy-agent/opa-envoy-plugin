# Copyright 2018 The OPA Authors. All rights reserved.
# Use of this source code is governed by an Apache2
# license that can be found in the LICENSE file.

FROM gcr.io/distroless/base

MAINTAINER Ashutosh Narkar  <anarkar4387@gmail.com>

WORKDIR /app

COPY opa_istio_linux_GOARCH /app

COPY opa_istio_plugin.so /app

ENTRYPOINT ["./opa_istio_linux_GOARCH"]

CMD ["run"]
