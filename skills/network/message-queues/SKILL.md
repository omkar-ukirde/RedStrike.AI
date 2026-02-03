---
name: message-queues
description: Skills for attacking message queue and IoT messaging services including MQTT, AMQP, and Kafka.
compatibility: Requires mosquitto-clients, pika, kafkacat
allowed-tools: mosquitto-clients kafkacat amqp-tools
metadata:
  category: network
---

# Message Queues

Message broker and pub/sub system exploitation.

## Skills

- [MQTT Pentesting](references/mqtt-pentesting.md) - MQTT broker (1883)
- [AMQP/RabbitMQ](references/amqp-rabbitmq-pentesting.md) - RabbitMQ (5672/15672)
- [Kafka Pentesting](references/kafka-pentesting.md) - Apache Kafka (9092)

## Quick Reference

| Service | Port | Key Attack |
|---------|------|------------|
| MQTT | 1883 | Subscribe #, no auth |
| RabbitMQ | 5672 | guest:guest |
| Kafka | 9092 | No auth, consume topics |
