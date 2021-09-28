#########################################################################################
# This file is part of FIWARE CyberCAPTOR, instance of Cyber Security Generic Enabler   #
#  Copyright (C) 2012-2015  Thales Services S.A.S.,                                     #
#  20-22 rue Grande Dame Rose 78140 VELIZY-VILACOUBLAY FRANCE                           #
#                                                                                       #
# FIWARE CyberCAPTOR is free software; you can redistribute                             #  
# it and/or modify it under the terms of the GNU General Public License                 #
# as published by the Free Software Foundation; either version 3 of the License,        #
# or (at your option) any later version.                                                #
#                                                                                       #
# FIWARE CyberCAPTOR is distributed in the hope                                         #
# that it will be useful, but WITHOUT ANY WARRANTY; without even the implied            #
# warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the             #
# GNU General Public License for more details.                                          #
#                                                                                       #
# You should have received a copy of the GNU General Public License                     #
# along with FIWARE Cyber Security Generic Enabler.                                     #
# If not, see <http://www.gnu.org/licenses/>.                                           #
#########################################################################################

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker, Session
from sqlalchemy.ext.declarative import declarative_base
import os

database_default_path = "./database-full.db"
engine = create_engine('sqlite:///' + str(os.getenv('VULNERABILITY_DATABASE_PATH', database_default_path)), convert_unicode=True, echo=False)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()


def init_db():
    # import all modules here that might define models so that
    # they will be registered properly on the metadata.  Otherwise
    # you will have to import them first before calling init_db()
    import models
    Base.metadata.create_all(bind=engine)
