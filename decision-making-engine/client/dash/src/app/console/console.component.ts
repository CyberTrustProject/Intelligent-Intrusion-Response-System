import { Component, OnInit } from '@angular/core';
import { HistoryService } from '../history.service';
import { SocketService } from '../socket.service';

@Component({
  selector: 'app-console',
  templateUrl: './console.component.html',
  styleUrls: ['./console.component.css']
})
export class ConsoleComponent implements OnInit {
  content = '';

  constructor(private socket: SocketService) { }

  ngOnInit() {
    this.socket.log.subscribe(line => this.content += `${line}\n`);
  }

}
