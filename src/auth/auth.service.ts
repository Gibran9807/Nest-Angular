import { BadRequestException, Injectable, UnauthorizedException } from '@nestjs/common';
import { InjectModel } from '@nestjs/mongoose';
import { User } from './entities/user.entity';
import { Model } from 'mongoose';
import { RegisterDto, LoginDto, UpdateAuthDto, CreateUserDto } from './dto';


import * as bcrypt from 'bcryptjs';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload';
import { LoginResponse } from './interfaces/login-response';



@Injectable()
export class AuthService {

  constructor(
    @InjectModel(User.name)
    private userModel: Model<User>,
    private jwtService: JwtService
  ) {

  }

  async create(createUserDto: CreateUserDto): Promise<User> {

    try {
      const{password, ...userData} = createUserDto; 

      const newUser = new this.userModel({
        // Encriptar contraseña
        password: bcrypt.hashSync(password, 10),
        ...userData
      });

      // Guardar el usuario
      await newUser.save();
      const {  password:_ , ...user} = newUser.toJSON();

      return user

    } catch (error) {

      if (error.code === 11000) {
        throw new BadRequestException(`${createUserDto.email} ya existe`);
      } 
      throw new BadRequestException('Error al crear el usuario')        
    }
  }

  async register(registerDto: RegisterDto): Promise<LoginResponse>{

    const user = await this.create(registerDto);

    return {
      user: user,
      token: this.getJWT({id: user._id})
    }
  }

  async login(loginDto: LoginDto): Promise<LoginResponse>{

    const {email, password} = loginDto;

    const user = await this.userModel.findOne({email});

    if(!user){
      throw new UnauthorizedException('Usuario o contraseña incorrectos');
    }

    if(!bcrypt.compareSync(password, user.password)){
      throw new UnauthorizedException('Usuario o contraseña incorrectos');
    }

    const { password:_ , ...rest } = user.toJSON();

    return {
      user: rest,
      token: this.getJWT({id: user.id})
    }
    
  }


  findAll(): Promise<User[]> {
    return this.userModel.find();
  }

  async findUserById(id: string): Promise<User> {
    const user = await this.userModel.findById(id);
    const {password, ...rest} = user.toJSON();

    return rest;
  }

  findOne(id: number) {
    return `This action returns a #${id} auth`;
  }

  update(id: number, updateAuthDto: UpdateAuthDto) {
    return `This action updates a #${id} auth`;
  }

  remove(id: number) {
    return `This action removes a #${id} auth`;
  }

  getJWT(payload: JwtPayload){
    const token = this.jwtService.sign(payload);
    return token;
  }
}
