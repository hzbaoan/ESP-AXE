import { HttpClient, HttpErrorResponse } from '@angular/common/http';
import { Component, Input, OnInit } from '@angular/core';
import { FormBuilder, FormGroup, Validators } from '@angular/forms';
import { ToastrService } from 'ngx-toastr';
import { finalize } from 'rxjs/operators';
import { DialogService } from 'src/app/services/dialog.service';
import { LoadingService } from 'src/app/services/loading.service';
import { SystemService } from 'src/app/services/system.service';

interface WifiNetwork {
  ssid: string;
  rssi: number;
  authmode: number;
}

@Component({
  selector: 'app-network-edit',
  templateUrl: './network.edit.component.html',
  styleUrls: ['./network.edit.component.scss']
})
export class NetworkEditComponent implements OnInit {

  public form!: FormGroup;
  public savedChanges: boolean = false;
  public scanning: boolean = false;

  @Input() uri = '';

  constructor(
    private fb: FormBuilder,
    private systemService: SystemService,
    private toastr: ToastrService,
    private toastrService: ToastrService,
    private loadingService: LoadingService,
    private http: HttpClient,
    private dialogService: DialogService
  ) {

  }
  ngOnInit(): void {
    this.systemService.getInfo(this.uri)
      .pipe(this.loadingService.lockUIUntilComplete())
      .subscribe(info => {
        this.form = this.fb.group({
          hostname: [info.hostname, [Validators.required]],
          ssid: [info.ssid, [Validators.required]],
          wifiPass: ['*****'],
          socks5ProxyEnabled: [Number(info.socks5ProxyEnabled ?? 0) === 1],
          socks5ProxyHost: [info.socks5ProxyHost ?? ''],
          socks5ProxyPort: [info.socks5ProxyPort ?? 1080],
          socks5ProxyUser: [info.socks5ProxyUser ?? ''],
          socks5ProxyPass: ['*****'],
        });
        this.applySocks5Validators();
        this.form.get('socks5ProxyEnabled')?.valueChanges.subscribe(() => this.applySocks5Validators());

      });
  }

  private applySocks5Validators() {
    const enabled = !!this.form?.get('socks5ProxyEnabled')?.value;
    const host = this.form.get('socks5ProxyHost');
    const port = this.form.get('socks5ProxyPort');

    host?.setValidators(enabled ? [
      Validators.required,
      Validators.pattern(/^(?!.*socks5:\/\/).*$/),
      Validators.pattern(/^[^:]*$/),
    ] : []);
    port?.setValidators(enabled ? [
      Validators.required,
      Validators.min(1),
      Validators.max(65535)
    ] : []);

    host?.updateValueAndValidity({ emitEvent: false });
    port?.updateValueAndValidity({ emitEvent: false });
  }

  public updateSystem() {

    const form = this.form.getRawValue();

    // Allow an empty wifi password
    form.wifiPass = form.wifiPass == null ? '' : form.wifiPass;

    if (form.wifiPass === '*****') {
      delete form.wifiPass;
    }

    // Trim SSID to remove any leading/trailing whitespace
    if (form.ssid) {
      form.ssid = form.ssid.trim();
    }

    form.socks5ProxyEnabled = form.socks5ProxyEnabled ? 1 : 0;
    form.socks5ProxyHost = form.socks5ProxyHost ? form.socks5ProxyHost.trim() : '';
    form.socks5ProxyUser = form.socks5ProxyUser ? form.socks5ProxyUser.trim() : '';

    if (form.socks5ProxyPass === '*****') {
      delete form.socks5ProxyPass;
    }

    this.systemService.updateSystem(this.uri, form)
      .pipe(this.loadingService.lockUIUntilComplete())
      .subscribe({
        next: () => {
          this.toastr.success('Success!', 'Saved.');
          this.savedChanges = true;
        },
        error: (err: HttpErrorResponse) => {
          this.toastr.error('Error.', `Could not save. ${err.message}`);
          this.savedChanges = false;
        }
      });
  }

  showWifiPassword: boolean = false;
  toggleWifiPasswordVisibility() {
    this.showWifiPassword = !this.showWifiPassword;
  }

  showSocks5ProxyPassword: boolean = false;
  toggleSocks5ProxyPasswordVisibility() {
    this.showSocks5ProxyPassword = !this.showSocks5ProxyPassword;
  }

  public scanWifi() {
    this.scanning = true;
    this.http.get<{networks: WifiNetwork[]}>('/api/system/wifi/scan')
      .pipe(
        finalize(() => this.scanning = false)
      )
      .subscribe({
        next: (response) => {
          // Sort networks by signal strength (highest first)
          const networks = response.networks.sort((a, b) => b.rssi - a.rssi);

          // filter out poor wifi connections
          const poorNetworks = networks.filter(network => network.rssi >= -80);

          // Remove duplicate Network Names and show highest signal strength only
          const uniqueNetworks = poorNetworks.reduce((acc, network) => {
            if (!acc[network.ssid] || acc[network.ssid].rssi < network.rssi) {
              acc[network.ssid] = network;
            }
            return acc;
          }, {} as { [key: string]: WifiNetwork });

          // Convert the object back to an array
          const filteredNetworks = Object.values(uniqueNetworks);

          // Create dialog data
          const dialogData = filteredNetworks.map(n => ({
            label: `${n.ssid} (${n.rssi}dBm)`,
            value: n.ssid
          }));

          // Show dialog with network list
          this.dialogService.open('Select WiFi Network', dialogData)
            .subscribe((selectedSsid: string) => {
              if (selectedSsid) {
                this.form.patchValue({ ssid: selectedSsid });
                this.form.markAsDirty();
              }
            });
        },
        error: (err) => {
          this.toastr.error('Failed to scan WiFi networks', 'Error');
        }
      });
  }

  public restart() {
    this.systemService.restart()
      .pipe(this.loadingService.lockUIUntilComplete())
      .subscribe({
        next: () => {
          this.toastr.success('Success!', 'Bitaxe restarted');
        },
        error: (err: HttpErrorResponse) => {
          this.toastr.error('Error', `Could not restart. ${err.message}`);
        }
      });
  }
}
