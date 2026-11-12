load("@bazel_gazelle//:deps.bzl", "go_repository")

def go_dependencies():
    go_repository(
        name = "com_example_upstream",
        importpath = "example.com/upstream",
        sum = "h1:SLqDtcPyVkkOYblt1rSVexJHaLWU/teyZ8o5mHyiUbA=",
        version = "v1.0.0",
    )
