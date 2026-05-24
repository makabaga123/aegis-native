FROM ubuntu:latest

ENV API_KEY=AKIA1234567890EXAMPLE
RUN apt-get update && apt-get install -y curl wget netcat openssh-server
RUN curl -fsSL https://example.com/install.sh | bash
ADD . /app
RUN chmod 777 /app
EXPOSE 22
WORKDIR /app
CMD ["python3", "app.py"]
