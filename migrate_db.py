"""
Database migration script to update schema.
"""
import os
import sys
import logging
from app import app, db
from models import Analysis, AttackPath

# Set up logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

def add_threat_details_column():
    """Add threat_details column to Analysis table if it doesn't exist."""
    from sqlalchemy import inspect, Column, Text
    
    try:
        inspector = inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('analysis')]
        
        if 'threat_details' not in columns:
            logger.info("Adding threat_details column to Analysis table")
            
            # Use raw SQL for the migration
            with db.engine.connect() as conn:
                conn.execute(db.text("ALTER TABLE analysis ADD COLUMN threat_details TEXT"))
                conn.commit()
                
            logger.info("Successfully added threat_details column")
        else:
            logger.info("threat_details column already exists")
            
        return True
    except Exception as e:
        logger.error(f"Error adding threat_details column: {e}")
        return False

def add_mitre_techniques_column():
    """Add mitre_techniques column to AttackPath table if it doesn't exist."""
    from sqlalchemy import inspect
    
    try:
        inspector = inspect(db.engine)
        columns = [col['name'] for col in inspector.get_columns('attack_path')]
        
        if 'mitre_techniques' not in columns:
            logger.info("Adding mitre_techniques column to AttackPath table")
            
            # Use raw SQL for the migration
            with db.engine.connect() as conn:
                conn.execute(db.text("ALTER TABLE attack_path ADD COLUMN mitre_techniques TEXT"))
                conn.commit()
                
            logger.info("Successfully added mitre_techniques column")
        else:
            logger.info("mitre_techniques column already exists")
            
        return True
    except Exception as e:
        logger.error(f"Error adding mitre_techniques column: {e}")
        return False

def run_migrations():
    """Run all database migrations."""
    with app.app_context():
        # Check if the database exists
        if not os.path.exists('instance/autonomous_threat_hunter.db'):
            logger.info("Database does not exist, creating tables")
            db.create_all()
            logger.info("Database tables created successfully")
        else:
            logger.info("Updating existing database schema")
            
            # Add threat_details column to Analysis table
            add_threat_details_column()
            
            # Add mitre_techniques column to AttackPath table
            add_mitre_techniques_column()
            
            logger.info("Database migration completed")

if __name__ == "__main__":
    run_migrations()