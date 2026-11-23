"""Connection admission and absolute header deadlines around uvicorn's h11 parser."""

from uvicorn.protocols.http.h11_impl import H11Protocol


class BoundedH11Protocol(H11Protocol):
    def __init__(self, *args, connection_limit, header_timeout, **kwargs):
        super().__init__(*args, **kwargs)
        self.connection_limit = connection_limit
        self.header_timeout = header_timeout
        self.header_deadline = None
        self.admitted = False

    def connection_made(self, transport):
        if len(self.connections) >= self.connection_limit:
            # Do not register rejected sockets or let their bytes reach the parser.
            transport.close()
            return
        self.admitted = True
        super().connection_made(transport)
        self.arm_header_deadline()

    def arm_header_deadline(self):
        self.cancel_header_deadline()
        if not self.transport.is_closing():
            self.header_deadline = self.loop.call_later(self.header_timeout, self.expire_headers)

    def cancel_header_deadline(self):
        if self.header_deadline is not None:
            self.header_deadline.cancel()
            self.header_deadline = None

    def expire_headers(self):
        self.header_deadline = None
        self.transport.close()

    def data_received(self, data):
        if self.admitted:
            super().data_received(data)

    def handle_events(self):
        previous = self.cycle
        super().handle_events()
        # A new cycle means h11 parsed complete headers. Partial bytes never rearm
        # the deadline; body/response time is governed by the application instead.
        if self.cycle is not previous:
            self.cancel_header_deadline()

    def on_response_complete(self):
        # Cover subsequent headers as well as the initial request. Arm before
        # uvicorn handles pipelined events, which may immediately complete headers.
        self.arm_header_deadline()
        super().on_response_complete()

    def connection_lost(self, exc):
        self.cancel_header_deadline()
        if self.admitted:
            super().connection_lost(exc)

    def shutdown(self):
        self.cancel_header_deadline()
        super().shutdown()
