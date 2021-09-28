import { BrowserModule } from '@angular/platform-browser';
import {BrowserAnimationsModule} from '@angular/platform-browser/animations';
import { NgModule } from '@angular/core';

import { AppComponent } from './app.component';

import {MatToolbarModule} from '@angular/material/toolbar';
import {MatIconModule} from '@angular/material/icon';
import {MatSidenavModule} from '@angular/material/sidenav';
import { MatSliderModule} from '@angular/material/slider';
import { MatProgressBarModule } from '@angular/material/progress-bar';
import { MatFormFieldModule} from '@angular/material/form-field';
import { MatInputModule} from '@angular/material/input';
import {MatButtonModule} from '@angular/material/button';
import { GraphComponent } from './graph/graph.component';
import { MatChipsModule} from '@angular/material/chips';
import { HistoryLockComponent } from './history-lock/history-lock.component';
import { DashComponent } from './dash/dash.component';
import { FormsModule } from '@angular/forms';
import { ConsoleComponent } from './console/console.component';
import { LatencyComponent } from './latency/latency.component';
import { UrlComponent } from './url/url.component';
import { StepCountComponent } from './step-count/step-count.component';
import { AlertsComponent } from './alerts/alerts.component';


@NgModule({
  declarations: [
    AppComponent,
    GraphComponent,
    HistoryLockComponent,
    DashComponent,
    ConsoleComponent,
    LatencyComponent,
    UrlComponent,
    StepCountComponent,
    AlertsComponent
  ],
  imports: [
    BrowserModule,
    BrowserAnimationsModule,
    FormsModule,
    MatToolbarModule,
    MatIconModule,
    MatSidenavModule,
    MatSliderModule,
    MatProgressBarModule,
    MatInputModule,
    MatFormFieldModule,
    MatButtonModule,
    MatChipsModule
  ],
  providers: [
  ],
  bootstrap: [AppComponent]
})
export class AppModule { }
