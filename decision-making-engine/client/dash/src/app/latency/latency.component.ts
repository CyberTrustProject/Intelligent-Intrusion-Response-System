import { Component, OnInit } from '@angular/core';
import { SocketService } from '../socket.service';

@Component({
  selector: 'app-latency',
  templateUrl: './latency.component.html',
  styleUrls: ['./latency.component.css']
})
export class LatencyComponent implements OnInit {

  latency = 'pending...';

  constructor(private socket: SocketService) {
    this.socket.latency.subscribe(median => this.latency = Math.round(median / 60 * 1000) / 1000 + ' seconds');
  }

  ngOnInit() {
  }

}
