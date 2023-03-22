package org.apache.phoenix.pherf.exception;

public class RowCountMismatchException extends PherfException {
    public RowCountMismatchException(String message) throws Exception {
        super(message);
    }

    public RowCountMismatchException(String message, Exception e) {
        super(message, e);
    }
}