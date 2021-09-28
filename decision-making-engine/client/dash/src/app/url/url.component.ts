import { Component, OnInit } from '@angular/core';
import { SocketService } from '../socket.service';

@Component({
  selector: 'app-url',
  templateUrl: './url.component.html',
  styleUrls: ['./url.component.css']
})
export class UrlComponent implements OnInit {

  // url = 'ws:172.16.4.30:8088';
  url = 'ws:localhost:8088';

  constructor(public socket: SocketService) {
  }

  ngOnInit() {
  }
}
