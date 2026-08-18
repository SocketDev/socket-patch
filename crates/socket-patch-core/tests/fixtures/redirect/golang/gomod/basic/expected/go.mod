module example.com/app

go 1.21

require github.com/foo/bar v1.4.2

replace github.com/foo/bar v1.4.2 => patch.socket.dev/gopatch/55555555-5555-5555-5555-555555555555 v1.4.2-socketpatch.1
