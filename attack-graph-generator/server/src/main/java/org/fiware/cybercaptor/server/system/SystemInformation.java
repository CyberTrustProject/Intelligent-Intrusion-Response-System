package org.fiware.cybercaptor.server.system;


public class SystemInformation {
    // Initialization information.
    private boolean initializedState = false;
    private long initializedDate = 0;

    public SystemInformation() {
        this.setInitializedDateNow();
    }

    public boolean getInitializedState() {
        return initializedState;
    }

    public void setInitializedState(boolean initializedState) {
        this.initializedState = initializedState;
    }

    public long getInitializedDate() {
        return initializedDate;
    }

    public void setInitializedDate(long initializedDate) {
        this.initializedDate = initializedDate;
    }

    public void setInitializedDateNow() {
        this.initializedDate = System.currentTimeMillis() / 1000L;
    }
}
