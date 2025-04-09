import {
    Entity,
    Column,
    PrimaryGeneratedColumn,
    CreateDateColumn,
    UpdateDateColumn,
    OneToOne,
    JoinColumn,
  } from 'typeorm';
  import { User } from './user.entity';
  
  @Entity('user_profiles')
  export class UserProfile {
    @PrimaryGeneratedColumn('uuid')
    id: string;
  
    @Column({ type: 'uuid' })
    userId: string;
  
    @Column({ nullable: true })
    address?: string;
  
    @Column({ nullable: true })
    city?: string;
  
    @Column({ nullable: true })
    state?: string;
  
    @Column({ nullable: true })
    country?: string;
  
    @Column({ nullable: true })
    postalCode?: string;
  
    @Column({ nullable: true })
    dateOfBirth?: Date;
  
    @Column({ nullable: true })
    nationality?: string;
  
    @Column({ nullable: true })
    occupation?: string;
  
    @Column({ nullable: true })
    employer?: string;
  
    @Column({ type: 'text', nullable: true })
    bio?: string;
  
    @Column({ nullable: true })
    avatarUrl?: string;
  
    @CreateDateColumn()
    createdAt: Date;
  
    @UpdateDateColumn()
    updatedAt: Date;
  
    // Relationships
    @OneToOne(() => User, user => user.profile)
    @JoinColumn({ name: 'userId' })
    user: User;
  }
  
 