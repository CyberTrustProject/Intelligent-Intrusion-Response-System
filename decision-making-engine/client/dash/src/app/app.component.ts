import { Component, ViewChild, OnInit } from '@angular/core';
import { MatDrawer } from '@angular/material/sidenav';

@Component({
  selector: 'app-root',
  templateUrl: './app.component.html',
  styleUrls: ['./app.component.css']
})
export class AppComponent implements OnInit {

  @ViewChild(MatDrawer) drawer: MatDrawer;

  title = 'dash';
  showFiller = false;

  ngOnInit() {
    this.drawer.toggle();
  }
}
