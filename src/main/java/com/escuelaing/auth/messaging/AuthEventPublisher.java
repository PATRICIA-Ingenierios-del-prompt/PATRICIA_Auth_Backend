package com.escuelaing.auth.messaging;

import com.escuelaing.auth.dto.event.AuthEvent;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthEventPublisher {

    private final RabbitTemplate rabbitTemplate;

    @Value("${messaging.exchange}")
    private String exchange;

    public void publish(String routingKey, AuthEvent event) {
        rabbitTemplate.convertAndSend(exchange, routingKey, event);
        log.debug("Auth event published type={} routingKey={}",
                event.tipo(), routingKey);
    }
}
