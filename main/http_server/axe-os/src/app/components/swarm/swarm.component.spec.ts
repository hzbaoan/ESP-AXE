import { HttpClientTestingModule } from '@angular/common/http/testing';
import { NO_ERRORS_SCHEMA } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ReactiveFormsModule } from '@angular/forms';
import { ToastrService } from 'ngx-toastr';

import { SwarmComponent } from './swarm.component';
import { LocalStorageService } from 'src/app/local-storage.service';
import { SystemService } from 'src/app/services/system.service';

describe('SwarmComponent', () => {
  let component: SwarmComponent;
  let fixture: ComponentFixture<SwarmComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [SwarmComponent],
      imports: [HttpClientTestingModule, ReactiveFormsModule],
      providers: [
        LocalStorageService,
        { provide: SystemService, useValue: jasmine.createSpyObj('SystemService', ['getInfo', 'restart']) },
        { provide: ToastrService, useValue: jasmine.createSpyObj('ToastrService', ['success', 'error', 'warning']) }
      ],
      schemas: [NO_ERRORS_SCHEMA]
    });
    TestBed.overrideComponent(SwarmComponent, { set: { template: '' } });
    fixture = TestBed.createComponent(SwarmComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
