import { NO_ERRORS_SCHEMA } from '@angular/core';
import { HttpClientTestingModule } from '@angular/common/http/testing';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ReactiveFormsModule } from '@angular/forms';
import { of } from 'rxjs';
import { ToastrService } from 'ngx-toastr';

import { SettingsComponent } from './settings.component';
import { GithubUpdateService } from 'src/app/services/github-update.service';
import { LoadingService } from 'src/app/services/loading.service';
import { SystemService } from 'src/app/services/system.service';

const mockSystemService = {
  getInfo: () => of({
    ASICModel: 'BM1366',
    flipscreen: 1,
    invertscreen: 0,
    stratumURL: 'pool.example',
    stratumPort: 3333,
    stratumUser: 'user',
    coreVoltage: 1200,
    frequency: 485,
    autofanspeed: 1,
    invertfanpolarity: 1,
    fanspeed: 100
  })
};

describe('SettingsComponent', () => {
  let component: SettingsComponent;
  let fixture: ComponentFixture<SettingsComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [SettingsComponent],
      imports: [HttpClientTestingModule, ReactiveFormsModule],
      providers: [
        LoadingService,
        { provide: GithubUpdateService, useValue: { getReleases: () => of([]) } },
        { provide: SystemService, useValue: mockSystemService },
        { provide: ToastrService, useValue: jasmine.createSpyObj('ToastrService', ['success', 'error']) }
      ],
      schemas: [NO_ERRORS_SCHEMA]
    });
    TestBed.overrideComponent(SettingsComponent, { set: { template: '' } });
    fixture = TestBed.createComponent(SettingsComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
