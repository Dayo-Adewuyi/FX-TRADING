 import {
    Entity,
    Column,
    PrimaryGeneratedColumn,
    CreateDateColumn,
    UpdateDateColumn,
    ManyToOne,
    JoinColumn,
    Index,
  } from 'typeorm';
  import { User } from './user.entity';
  
  export enum DocumentType {
    PASSPORT = 'passport',
    DRIVERS_LICENSE = 'drivers_license',
    NATIONAL_ID = 'national_id',
    UTILITY_BILL = 'utility_bill',
    BANK_STATEMENT = 'bank_statement',
    OTHER = 'other',
  }
  
  export enum DocumentStatus {
    PENDING = 'pending',
    APPROVED = 'approved',
    REJECTED = 'rejected',
  }
  
  @Entity('kyc_documents')
  export class KycDocument {
    @PrimaryGeneratedColumn('uuid')
    id: string;
  
    @Column({ type: 'uuid' })
    @Index()
    userId: string;
  
    @Column({ type: 'enum', enum: DocumentType })
    documentType: DocumentType;
  
    @Column({ length: 255 })
    documentNumber: string;
  
    @Column({ type: 'date', nullable: true })
    expiryDate?: Date;
  
    @Column({ length: 255 })
    documentUrl: string;
  
    @Column({ type: 'enum', enum: DocumentStatus, default: DocumentStatus.PENDING })
    status: DocumentStatus;
  
    @Column({ type: 'text', nullable: true })
    rejectionReason?: string;
  
    @Column({ nullable: true })
    verifiedAt?: Date;
  
    @Column({ nullable: true })
    verifiedBy?: string;
  
    @CreateDateColumn()
    createdAt: Date;
  
    @UpdateDateColumn()
    updatedAt: Date;
  
    // Relationships
    @ManyToOne(() => User, user => user.kycDocuments)
    @JoinColumn({ name: 'userId' })
    user: User;
  }
  
  