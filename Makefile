build:
	@ echo "building..."
	@ go build -o bin/main cmd/api/main.go

run:
	@ echo "running..."
	@ go run cmd/api/main.go

clean:
	@ echo "cleaning..."
	@ rm ./bin/*