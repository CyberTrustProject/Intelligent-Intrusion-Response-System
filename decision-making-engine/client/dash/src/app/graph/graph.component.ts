import { Component, OnInit, Input } from '@angular/core';
import { state } from '@angular/animations';
import { HistoryService } from '../history.service';
import { Observable } from 'rxjs';
import { DomSanitizer, SafeHtml } from '@angular/platform-browser';


@Component({
  selector: 'app-graph',
  templateUrl: './graph.component.html',
  styleUrls: ['./graph.component.css']
})
export class GraphComponent implements OnInit {

  title = '';
  max: Observable<number>;
  step: Observable<number>;
  content: SafeHtml = '';

  @Input() type: string;

  constructor(public history: HistoryService, private sanitizer: DomSanitizer) {
  }

  ngOnInit() {
    this.title = this.type === 'state' ? 'Real state' : this.type === 'belief' ? 'Belief' : 'Plot';
    this.max = this.history[`${this.type}Count`];
    this.step = this.history[`${this.type}CurrentStep`];
    this.history[this.type].subscribe(v => {
      this.content = this.sanitizer.bypassSecurityTrustHtml(v);
    });
  }

  recall(e) {
    this.history[`${this.type}Recall`](e.value - 1);
  }

}
