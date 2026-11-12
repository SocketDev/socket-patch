module example.com/consumer

go 1.21

require (
	example.com/local v0.0.0
	example.com/upstream v1.0.0
)

replace example.com/local => ./third_party/local
