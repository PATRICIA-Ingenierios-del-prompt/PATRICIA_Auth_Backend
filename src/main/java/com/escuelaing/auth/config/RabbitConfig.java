package com.escuelaing.auth.config;

import org.springframework.amqp.core.Binding;
import org.springframework.amqp.core.BindingBuilder;
import org.springframework.amqp.core.Queue;
import org.springframework.amqp.core.TopicExchange;
import org.springframework.amqp.rabbit.connection.ConnectionFactory;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.amqp.support.converter.Jackson2JsonMessageConverter;
import org.springframework.amqp.support.converter.MessageConverter;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class RabbitConfig {

    @Bean
    public TopicExchange authExchange(
            @Value("${messaging.exchange}") String exchange
    ) {
        return new TopicExchange(exchange, true, false);
    }

    @Bean
    public TopicExchange usuariosExchange(
            @Value("${messaging.usuarios-exchange}") String exchange
    ) {
        return new TopicExchange(exchange, true, false);
    }

    @Bean
    public Queue usuariosSuspendidosQueue(
            @Value("${messaging.queues.usuarios-suspendidos}") String queue
    ) {
        return new Queue(queue, true, false, false);
    }

    @Bean
    public Queue usuariosBaneadosQueue(
            @Value("${messaging.queues.usuarios-baneados}") String queue
    ) {
        return new Queue(queue, true, false, false);
    }

    @Bean
    public Binding usuariosSuspendidosBinding(
            @Qualifier("usuariosSuspendidosQueue") Queue queue,
            @Qualifier("usuariosExchange") TopicExchange exchange
    ) {
        return BindingBuilder.bind(queue)
                .to(exchange)
                .with("usuario.suspendido");
    }

    @Bean
    public Binding usuariosBaneadosBinding(
            @Qualifier("usuariosBaneadosQueue") Queue queue,
            @Qualifier("usuariosExchange") TopicExchange exchange
    ) {
        return BindingBuilder.bind(queue)
                .to(exchange)
                .with("usuario.baneado");
    }

    @Bean
    public MessageConverter messageConverter() {
        return new Jackson2JsonMessageConverter();
    }

    @Bean
    public RabbitTemplate rabbitTemplate(
            ConnectionFactory connectionFactory,
            MessageConverter messageConverter
    ) {
        RabbitTemplate rabbitTemplate = new RabbitTemplate(connectionFactory);
        rabbitTemplate.setMessageConverter(messageConverter);
        return rabbitTemplate;
    }
}
