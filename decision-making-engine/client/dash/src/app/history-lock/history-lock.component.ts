import { Component, OnInit } from '@angular/core';
import { HistoryService } from '../history.service';

@Component({
  selector: 'app-history-lock',
  templateUrl: './history-lock.component.html',
  styleUrls: ['./history-lock.component.css']
})
export class HistoryLockComponent implements OnInit {

  constructor(public history: HistoryService) { }

  ngOnInit() {
  }

  toggle() {
    this.history.synchronized = !this.history.synchronized;
  }

}
