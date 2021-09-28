/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package org.fiware.cybercaptor.server.attackgraph;

/**
 * Exception thrown when there is no MulVAL attack graph XML file generated.
*/
public class MulvalEmptyAttackGraphException extends Exception {
    public MulvalEmptyAttackGraphException(String errorMessage) {
        super(errorMessage);
    }

    public MulvalEmptyAttackGraphException(String errorMessage, Throwable throwable) {
        super(errorMessage, throwable);
    }
}