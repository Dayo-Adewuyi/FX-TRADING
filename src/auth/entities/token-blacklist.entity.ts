import { 
    Column, 
    CreateDateColumn, 
    Entity, 
    Index, 
    PrimaryGeneratedColumn 
  } from 'typeorm';
  
  @Entity('token_blacklist')
  export class TokenBlacklist {
    @PrimaryGeneratedColumn('uuid')
    id: string;
  
    @Column({ type: 'varchar', length: 500 })
    @Index()
    token: string;
  
    @Column({ type: 'varchar', length: 36 })
    @Index()
    userId: string;
  
    @Column({ type: 'timestamp with time zone' })
    @Index()
    expiresAt: Date;
  
    @CreateDateColumn()
    createdAt: Date;
  }
  
 