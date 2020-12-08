FROM golang:1.15
WORKDIR /src
COPY . /src
RUN go build .
CMD ["/src/testsrv", "--port", "9090"]
EXPOSE 9090
