# -*- coding: utf-8 -*-
"""
Created on Wed Dec  2 22:36:32 2020

@author: Westbrook#44.feng
"""
#Create/Write Users & Votes to Database
Users={}
#read users' information first
def create_users(Username,Password):
    Users[Username]=Password
Ballots={}
#read users' ballot
def Write_votes(Username,Candicate):
    Ballots[Username]=Candicate
#The problem is how to extract username and password from data.    
    
    
