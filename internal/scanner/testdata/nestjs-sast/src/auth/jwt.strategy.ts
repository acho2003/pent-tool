import { Injectable } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor() {
    // ruleid: nestjs-jwt-ignore-expiration
    // ruleid: nestjs-jwt-hardcoded-secret
    super({ jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(), ignoreExpiration: true, secretOrKey: process.env.JWT_SECRET || 'fallback-secret' });
  }
}
