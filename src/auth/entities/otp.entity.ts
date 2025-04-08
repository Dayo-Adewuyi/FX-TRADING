 import { 
    Column, 
    CreateDateColumn, 
    Entity, 
    Index, 
    PrimaryGeneratedColumn 
  } from 'typeorm';
  import { OtpAction } from '../dtos/request-otp.dto';
  
  @Entity('otps')
  export class OtpEntity {
    @PrimaryGeneratedColumn('uuid')
    id: string;
  
    @Column({ type: 'varchar', length: 36 })
    @Index()
    userId: string;
  
    @Column({ type: 'enum', enum: OtpAction })
    @Index()
    action: OtpAction;
  
    @Column({ type: 'varchar', length: 6 })
    otp: string;
  
    @Column({ type: 'int', default: 0 })
    attempts: number;
  
    @Column({ type: 'boolean', default: false })
    isVerified: boolean;
  
    @Column({ type: 'timestamp with time zone' })
    @Index()
    expiresAt: Date;
  
    @CreateDateColumn()
    createdAt: Date;
  }
  
  