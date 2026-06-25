import { HttpErrorResponse } from '@angular/common/http';
import { Component, Input, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, ValidatorFn, Validators } from '@angular/forms';
import { ToastrService } from 'ngx-toastr';
import { LoadingService } from 'src/app/services/loading.service';
import { SystemService } from 'src/app/services/system.service';

@Component({
  selector: 'app-pool',
  templateUrl: './pool.component.html',
  styleUrls: ['./pool.component.scss']
})
export class PoolComponent implements OnInit {
  public form!: FormGroup;
  public savedChanges: boolean = false;

  @Input() uri = '';

  constructor(
    private fb: FormBuilder,
    private systemService: SystemService,
    private toastr: ToastrService,
    private loadingService: LoadingService
  ) {}

  ngOnInit(): void {
    this.systemService.getInfo(this.uri)
      .pipe(
        this.loadingService.lockUIUntilComplete()
      )
      .subscribe(info => {
        this.form = this.fb.group({
          stratumProtocol: [info.stratumProtocol ?? 1, [Validators.required]],
          stratumURL: [info.stratumURL, [
            Validators.required,
            Validators.pattern(/^(?!.*stratum\+tcp:\/\/).*$/),
            Validators.pattern(/^[^:]*$/),
          ]],
          stratumPort: [info.stratumPort, [
            Validators.required,
            Validators.pattern(/^[^:]*$/),
            Validators.min(0),
            Validators.max(65353)
          ]],
          fallbackStratumURL: [info.fallbackStratumURL, [
            Validators.pattern(/^(?!.*stratum\+tcp:\/\/).*$/),
          ]],
          fallbackStratumPort: [info.fallbackStratumPort, [
            Validators.required,
            Validators.pattern(/^[^:]*$/),
            Validators.min(0),
            Validators.max(65353)
          ]],
          fallbackStratumProtocol: [info.fallbackStratumProtocol ?? 1, [Validators.required]],
          stratumUser: [info.stratumUser, [Validators.required]],
          stratumPassword: ['*****', [Validators.required]],
          fallbackStratumUser: [info.fallbackStratumUser, [Validators.required]],
          fallbackStratumPassword: ['*****', [Validators.required]],
          sv2Host: [info.sv2Host, [
            Validators.pattern(/^(?!.*stratum\+tcp:\/\/).*$/),
            Validators.pattern(/^[^:]*$/),
          ]],
          sv2Port: [info.sv2Port],
          sv2AuthorityPublicKey: [info.sv2AuthorityPublicKey],
          fallbackSv2Host: [info.fallbackSv2Host, [
            Validators.pattern(/^(?!.*stratum\+tcp:\/\/).*$/),
            Validators.pattern(/^[^:]*$/),
          ]],
          fallbackSv2Port: [info.fallbackSv2Port],
          fallbackSv2AuthorityPublicKey: [info.fallbackSv2AuthorityPublicKey]
        });
        this.applyProtocolValidators();
        this.form.get('stratumProtocol')?.valueChanges.subscribe(() => this.applyProtocolValidators());
        this.form.get('fallbackStratumProtocol')?.valueChanges.subscribe(() => this.applyProtocolValidators());
      });
  }

  public get primaryUsesSv2(): boolean {
    return Number(this.form?.get('stratumProtocol')?.value) === 2;
  }

  public get fallbackUsesSv2(): boolean {
    return Number(this.form?.get('fallbackStratumProtocol')?.value) === 2;
  }

  private applyProtocolValidators() {
    const primarySv2Required = this.primaryUsesSv2;
    const fallbackSv2Required = this.fallbackUsesSv2;

    this.setProtocolValidators('stratumURL', !primarySv2Required, [
      Validators.pattern(/^(?!.*stratum\+tcp:\/\/).*$/),
      Validators.pattern(/^[^:]*$/),
    ]);
    this.setProtocolValidators('stratumPort', !primarySv2Required, [
      Validators.pattern(/^[^:]*$/),
      Validators.min(0),
      Validators.max(65353)
    ]);
    this.setProtocolValidators('stratumUser', !primarySv2Required);
    this.setProtocolValidators('stratumPassword', !primarySv2Required);

    this.setProtocolValidators('sv2Host', primarySv2Required, [
      Validators.pattern(/^(?!.*stratum\+tcp:\/\/).*$/),
      Validators.pattern(/^[^:]*$/),
    ]);
    this.setProtocolValidators('sv2Port', primarySv2Required, [
      Validators.pattern(/^[^:]*$/),
      Validators.min(1),
      Validators.max(65535)
    ]);
    this.setProtocolValidators('sv2AuthorityPublicKey', primarySv2Required);

    this.setProtocolValidators('fallbackStratumURL', !fallbackSv2Required, [
      Validators.pattern(/^(?!.*stratum\+tcp:\/\/).*$/),
    ], false);
    this.setProtocolValidators('fallbackStratumPort', !fallbackSv2Required, [
      Validators.pattern(/^[^:]*$/),
      Validators.min(0),
      Validators.max(65353)
    ]);
    this.setProtocolValidators('fallbackStratumUser', !fallbackSv2Required);
    this.setProtocolValidators('fallbackStratumPassword', !fallbackSv2Required);

    this.setProtocolValidators('fallbackSv2Host', fallbackSv2Required, [
      Validators.pattern(/^(?!.*stratum\+tcp:\/\/).*$/),
      Validators.pattern(/^[^:]*$/),
    ]);
    this.setProtocolValidators('fallbackSv2Port', fallbackSv2Required, [
      Validators.pattern(/^[^:]*$/),
      Validators.min(1),
      Validators.max(65535)
    ]);
    this.setProtocolValidators('fallbackSv2AuthorityPublicKey', fallbackSv2Required);
  }

  private setProtocolValidators(controlName: string, enabled: boolean, validators: ValidatorFn[] = [], required = true) {
    const control = this.form.get(controlName);
    if (!control) {
      return;
    }

    control.setValidators(enabled ? [...(required ? [Validators.required] : []), ...validators] : []);
    control.updateValueAndValidity({ emitEvent: false });
  }

  public updateSystem() {
    const form = this.form.getRawValue();

    if (this.primaryUsesSv2) {
      delete form.stratumURL;
      delete form.stratumPort;
      delete form.stratumUser;
      delete form.stratumPassword;
    } else {
      delete form.sv2Host;
      delete form.sv2Port;
      delete form.sv2AuthorityPublicKey;

      if (form.stratumPassword === '*****') {
        delete form.stratumPassword;
      }
    }

    if (this.fallbackUsesSv2) {
      delete form.fallbackStratumURL;
      delete form.fallbackStratumPort;
      delete form.fallbackStratumUser;
      delete form.fallbackStratumPassword;
    } else {
      delete form.fallbackSv2Host;
      delete form.fallbackSv2Port;
      delete form.fallbackSv2AuthorityPublicKey;

      if (form.fallbackStratumPassword === '*****') {
        delete form.fallbackStratumPassword;
      }
    }

    this.systemService.updateSystem(this.uri, form)
      .pipe(this.loadingService.lockUIUntilComplete())
      .subscribe({
        next: () => {
          const successMessage = this.uri ? `Saved pool settings for ${this.uri}` : 'Saved pool settings';
          this.toastr.success(successMessage, 'Success!');
          this.savedChanges = true;
        },
        error: (err: HttpErrorResponse) => {
          const errorMessage = this.uri ? `Could not save pool settings for ${this.uri}. ${err.message}` : `Could not save pool settings. ${err.message}`;
          this.toastr.error(errorMessage, 'Error');
          this.savedChanges = false;
        }
      });
  }

  showStratumPassword: boolean = false;
  toggleStratumPasswordVisibility() {
    this.showStratumPassword = !this.showStratumPassword;
  }

  showFallbackStratumPassword: boolean = false;
  toggleFallbackStratumPasswordVisibility() {
    this.showFallbackStratumPassword = !this.showFallbackStratumPassword;
  }

  public restart() {
    this.systemService.restart(this.uri)
      .pipe(this.loadingService.lockUIUntilComplete())
      .subscribe({
        next: () => {
          const successMessage = this.uri ? `Bitaxe at ${this.uri} restarted` : 'Bitaxe restarted';
          this.toastr.success(successMessage, 'Success');
        },
        error: (err: HttpErrorResponse) => {
          const errorMessage = this.uri ? `Failed to restart device at ${this.uri}. ${err.message}` : `Failed to restart device. ${err.message}`;
          this.toastr.error(errorMessage, 'Error');
        }
      });
  }
}
