package de.unipassau.wolfgangpopp.xmlrss;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

/**
 * @author Wolfgang Popp
 */
public final class Message {

    private List<Part> parts = new ArrayList<Part>();

    public interface Part {
        byte[] getEncoded();
    }

    public static class Builder{

        private final Message message;

        public Builder(){
            message = new Message();
        }

        public void add(Part part) {
            message.parts.add(part);
        }

        public void addAll(Collection<Part> parts) {
            message.parts.addAll(parts);
        }


        public Message build(){
            return message;
        }

        // TODO: 10/26/16 add remove(), ...

    }

    public List<Part> getParts() {
        return new ArrayList<Part>(parts);
    }

    public Part getPart(int index) {
        return parts.get(index);
    }

    public int size() {
        return parts.size();
    }

}
