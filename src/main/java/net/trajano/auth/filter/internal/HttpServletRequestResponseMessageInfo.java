package net.trajano.auth.filter.internal;

import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.security.auth.message.MessageInfo;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * MessageInfo that contains HttpServletRequest and HttpServletResponse.
 */
public class HttpServletRequestResponseMessageInfo implements MessageInfo {
    /**
     * Map.
     */
    private final ConcurrentMap<?, ?> map = new ConcurrentHashMap<>();

    /**
     * Request.
     */
    private transient HttpServletRequest request;

    /**
     * Response.
     */
    private transient HttpServletResponse response;

    @Override
    public Map<?, ?> getMap() {
        return map;
    }

    @Override
    public Object getRequestMessage() {
        return request;
    }

    @Override
    public Object getResponseMessage() {
        return response;
    }

    @Override
    public void setRequestMessage(final Object requestMessage) {
        request = (HttpServletRequest) requestMessage;
    }

    @Override
    public void setResponseMessage(final Object responseMessage) {
        response = (HttpServletResponse) responseMessage;
    }

}
