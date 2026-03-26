FROM golang:1.24
WORKDIR /src
COPY . /src
RUN go build .
CMD ["/src/testsrv", "--port", "9090"]
EXPOSE 9090
