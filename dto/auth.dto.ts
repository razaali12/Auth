export class AuthDto {
  email: string;
  password: string;
}

export class ConfirmOtpDto {
  email: string;
  otp: number;
}

export class ChangePasswordDto {
  password: string;
  newPassword: string;
}
