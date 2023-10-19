class PrintRequestMiddleware:
    def __init__(self, get_response):
        self.get_response = get_response

    def __call__(self, request):
        # print("custom middleware before next middleware/view")
        response = self.get_response(request)
        # for i in request:
        #     print(i, request[i], dir(request), "recmd")
        # print(repr(request), type(request), "pcmd")
        try:
            if request.headers:
                print(request.headers, "headers")
                print("-------------------------------------------")
            if request.COOKIES:
                print(request.COOKIES, "COOKIES")
                print("-------------------------------------------")
                # if request.META:
                #     print(request.META, "META")
                #     print("-------------------------------------------")
                # if request.body:
                # print(request.body, "body")
                print("-------------------------------------------")
            if request.content_type:
                print(request.content_type, "content_type")
                print("-------------------------------------------")
            if request.session:
                print(request.session, "session")
                print("-------------------------------------------")
                # if request.auth:
                # print(request.auth, "auth")
                print("-------------------------------------------")
                # if request.user:
                # print(request.user, "user")
                print("-------------------------------------------")
        except Exception as e:
            print(e, "An exception occurred")
            print("-------------------------------------------")

        return response

        # Code to be executed for each request before
        # the view (and later middleware) are called.


# Code to be executed for each response after the view is called
#
