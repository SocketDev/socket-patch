module example.com/app

go 1.21

require (
	github.com/fx/alpha v1.0.0
	github.com/fx/beta v1.0.0
)

replace github.com/fx/alpha v1.0.0 => ./.socket/vendor/golang/11111111-1111-4111-8111-000000000001/github.com/fx/alpha@v1.0.0

replace github.com/fx/beta v1.0.0 => ./.socket/vendor/golang/11111111-1111-4111-8111-000000000002/github.com/fx/beta@v1.0.0
