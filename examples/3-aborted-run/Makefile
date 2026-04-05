.PHONY: test clean

test:
	docker compose up --build --abort-on-container-exit --exit-code-from test
	docker compose down --volumes

clean:
	docker compose down --volumes --rmi local
