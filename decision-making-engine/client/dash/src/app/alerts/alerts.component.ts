import { Component, OnInit } from '@angular/core';
import { HistoryService } from '../history.service';

@Component({
  selector: 'app-alerts',
  templateUrl: './alerts.component.html',
  styleUrls: ['./alerts.component.css']
})
export class AlertsComponent implements OnInit {

  alerts: Array<{ name: string, triggered: boolean}>;

  constructor(public history: HistoryService) { }

  ngOnInit() {
    this.history.triggeredAlerts.subscribe(a => this.alerts = a);
  }

}
