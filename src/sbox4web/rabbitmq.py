# -*- coding: utf-8 -*-
__author__ = 'TOANTV'
import pika
from django.conf import settings


class Rabbitmq:
    def __init__(self, queue):
        self.queue = queue
        self.maxPriority = 255
        self.create_connection()

    def __del__(self):
        self.connection.close()

    def create_connection(self):
        credentials = pika.PlainCredentials(settings.BROKER["user"], settings.BROKER["pass"])
        self.connection = pika.BlockingConnection(
            pika.ConnectionParameters(
                host=settings.BROKER["host"],
                port=settings.BROKER["port"],
                credentials=credentials)
        )

        self.channel = self.connection.channel()
        self.channel.queue_declare(queue=self.queue, durable=True)
        print "Connected to queue {}".format(str(self.queue))

    def message_count(self):
        queue = self.channel.queue_declare(
            queue=self.queue, durable=True,
            exclusive=False, auto_delete=False
        )
        return queue.method.message_count

    def add(self, message):
        self.channel.basic_publish(exchange='',
                                   routing_key=self.queue,
                                   body=message,
                                   properties=pika.BasicProperties(
                                       delivery_mode=2,  # make message longistent
                                   ))
        print "Added message {} to queue {}".format(str(message), str(self.queue))
        self.connection.close()

    def get(self):
        self.channel.basic_qos(prefetch_count=1)
        self.channel.basic_consume(self.callback, queue=self.queue)
        # self.channel.basic_consume(self.callback, queue=self.queue, no_ack=True)
        print "Start rabbitmq consumer, waiitting for messages from queue {}".format(self.queue)
        self.channel.start_consuming()

    def callback(self, ch, method, properties, body):
        ch.basic_ack(delivery_tag=method.delivery_tag)
