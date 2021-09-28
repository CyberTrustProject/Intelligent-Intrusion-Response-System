import { Component, OnInit } from '@angular/core';
import { HistoryService } from '../history.service';

@Component({
  selector: 'app-step-count',
  templateUrl: './step-count.component.html',
  styleUrls: ['./step-count.component.css']
})
export class StepCountComponent implements OnInit {

  constructor(public history: HistoryService) { 

  }

  ngOnInit() {
  }

}
