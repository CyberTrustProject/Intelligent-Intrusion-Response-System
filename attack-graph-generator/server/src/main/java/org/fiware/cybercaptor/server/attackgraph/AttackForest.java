package org.fiware.cybercaptor.server.attackgraph;

import org.fiware.cybercaptor.server.attackgraph.Arc;
import org.fiware.cybercaptor.server.attackgraph.AttackGraph;
import org.fiware.cybercaptor.server.attackgraph.Vertex;
import org.fiware.cybercaptor.server.attackgraph.VertexHostAssociation;
import org.fiware.cybercaptor.server.attackgraph.fact.DatalogCommand;
import org.fiware.cybercaptor.server.attackgraph.fact.Fact;
import org.fiware.cybercaptor.server.attackgraph.fact.Rule;


import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;


public class AttackForest extends AttackGraph {
	
	private int counter = 1;
	//public Vertex root  = null;
	
	private ArrayList<Vertex> roots = new ArrayList<Vertex>();
	private ArrayList<AttackGraph> trees = new ArrayList<AttackGraph>();
	
	public AttackForest(AttackGraph attackGraph) throws Exception {
		
		roots = attackGraph.findRootVertices();
//		for(int i = 0; i < roots.size(); i++) {
//			
//			Vertex root = roots.get(i).clone();
//			root.id = counter++;
//			
//			this.vertices.put(root.id, root);
//			 
//		}	
		
		for(int i = 0; i < this.roots.size(); i ++) {
			
			System.out.println(roots.get(i).toString());
			System.out.println("-------------------");
			
			//CREATE TREE
			AttackGraph tree = new AttackGraph();
			
			int tempID = 1;
			
			ArrayList<Arc> visitedArcs = new ArrayList<Arc>();
			ArrayList<Vertex> visitedVertices = new ArrayList<Vertex>();
			
			//FILL ARCS AND VERTICES
			
			tempID = dfs(roots.get(i).id,visitedVertices, visitedArcs, attackGraph,tempID);
			
			System.out.println("VERTICES:  " + visitedVertices.size());
			System.out.println("ARCS:      "+ visitedArcs.size());
			
			//FIND CONSTRUCT TREE
			for(int y = 0; y < visitedVertices.size(); y ++) {
				
				System.out.println(visitedVertices.get(y).toString());
				//visitedVertices.get(y).id = y;
				//TODO ERROR NEED TO CHECK LINE 60 BECAUSE OF 58
				tree.vertices.put(visitedVertices.get(y).id,visitedVertices.get(y)); 
			}
			
			for(int y = 0; y < visitedArcs.size(); y ++) {
				System.out.println(visitedArcs.get(y).toString());
				System.out.println(visitedArcs.get(y).destination.toString() + " -- " +visitedArcs.get(y).source.toString());
			}
			
			tree.computeAllParentsAndChildren();
		}
	}
	
	
	 private int dfs(int i, ArrayList<Vertex> visitedVertices, ArrayList<Arc> visitedArcs, AttackGraph ag, int tempID) throws Exception {
 	   	
		 	Vertex node = ag.getVertexFromId(i);
		 	
		 			
	        if (visitedVertices.contains(node)){
	        	tempID = tempID -1;
	            return tempID ; 
	        }
	        
	       
	        node.id = tempID;
	        visitedVertices.add(node);
	            
	        List<Vertex> parents= node.parents; 

	        
	         
	        for (int c = 0; c < parents.size(); c++){
	        	// ASSIGN NEW IDs
	        	
	        	tempID = tempID + 1;
	        	Vertex toADD = parents.get(c);
	        	toADD.id = tempID;
	        	
	        	visitedArcs.add(new Arc(toADD,node));
	        	
	            tempID = dfs(parents.get(c).id, visitedVertices,visitedArcs, ag,tempID);
	            

	        }

	        
	        return tempID ; 
	    }
	
}
