import { Injectable } from '@angular/core';
import { Subject, ReplaySubject } from 'rxjs';
import { HistoryService } from './history.service';

type ConnectionStatus = 'closed' | 'connecting' | 'connected' | 'disconnected';

@Injectable({
  providedIn: 'root'
})
export class SocketService {

  last = 0;

  status = new ReplaySubject<ConnectionStatus>(1);

  log = new Subject<string>();

  websocket: WebSocket;

  updateTimes = [];

  latency = new Subject<number>();

  constructor(private history: HistoryService) {
    this.status.next('closed');
  }

  doConnect(url: string) {
    this.status.next('connecting');
    this.log.next('connecting');
    this.websocket = new WebSocket(url);
    this.websocket.onopen = this.onOpen;
    this.websocket.onclose = this.onClose;
    this.websocket.onmessage = this.onMessage;
    this.websocket.onerror = this.onError;
  }

  onOpen = (e) => {
    this.status.next('connected');
    this.log.next('connected');
  }

  onClose = (e) => {
    this.status.next('disconnected');
    this.log.next('disconnected');
  }

  onMessage = (e) => {
    const now = this.logTime();
    this.log.next(`update: ${now.toLocaleString()}`);
    const data = JSON.parse(e.data);
    this.history.storeState(data.state);
    this.history.storeBelief(data.belief);
    this.history.storePlot(data.plot);
    this.history.storeAlert(data.alerts);
  }

  onError = (e) => {
    this.log.next(`error!`);
    this.websocket.close();
    this.status.next('disconnected');
  }

  doSend(message) {
    this.websocket.send(message);
    this.log.next(`sent: ${message}`);
  }


  doDisconnect() {
    this.websocket.close();
    this.status.next('disconnected');
  }

  logTime() {
    const now = new Date();
    const nowMillis = now.getUTCMilliseconds();

    if (this.updateTimes.length) {
      const sinceLast = nowMillis - this.last;
      this.updateTimes.push(sinceLast);
    } else {
      this.updateTimes.push(0);
    }

    this.last = nowMillis;

    this.latency.next(this.median(this.updateTimes));

    return now;
  }

  median(values: number[]) {
    values.sort(function (a, b) {
      return a - b;
    });

    if (values.length === 0) {
      return 0;
    }

    const half = Math.floor(values.length / 2);

    if (values.length % 2) {
      return values[half];
    } else {
      return (values[half - 1] + values[half]) / 2.0;
    }
  }

}
