import { HttpClientTestingModule } from '@angular/common/http/testing';
import { NO_ERRORS_SCHEMA } from '@angular/core';
import { ComponentFixture, TestBed } from '@angular/core/testing';
import { ReactiveFormsModule } from '@angular/forms';
import { of } from 'rxjs';
import { ToastrService } from 'ngx-toastr';

import { NetworkEditComponent } from './network.edit.component';
import { DialogService } from 'src/app/services/dialog.service';
import { LoadingService } from 'src/app/services/loading.service';
import { SystemService } from 'src/app/services/system.service';

describe('NetworkEditComponent', () => {
  let component: NetworkEditComponent;
  let fixture: ComponentFixture<NetworkEditComponent>;

  beforeEach(() => {
    TestBed.configureTestingModule({
      declarations: [NetworkEditComponent],
      imports: [HttpClientTestingModule, ReactiveFormsModule],
      providers: [
        LoadingService,
        { provide: DialogService, useValue: { open: () => of(null) } },
        { provide: SystemService, useValue: jasmine.createSpyObj('SystemService', ['getInfo', 'updateSystem', 'restart']) },
        { provide: ToastrService, useValue: jasmine.createSpyObj('ToastrService', ['success', 'error']) }
      ],
      schemas: [NO_ERRORS_SCHEMA]
    });
    TestBed.overrideComponent(NetworkEditComponent, { set: { template: '' } });
    fixture = TestBed.createComponent(NetworkEditComponent);
    component = fixture.componentInstance;
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
