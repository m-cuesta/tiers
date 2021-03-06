/**

com.cuesta.web.tags.BaseTag.java
Version: 1.0

********************************************************************************
Author:
Manuel Cuesta, programmer <camilocuesta@hotmail.com>

**************************************************

CuestaLib is Copyright (c) 2010, Manuel Cuesta  <camilocuesta@hotmail.com >
All rights reserved.

Published under the terms of the new BSD license.
See: [http://github.com/m-cuesta/tiers] for the full license and other info.

LICENSE:

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

Redistributions of source code must retain the above copyright notice,
this list of conditions and the following disclaimer.

Redistributions in binary form must reproduce the above copyright
notice, this list of conditions and the following disclaimer in the
documentation and/or other materials provided with the distribution.

Neither the name of Manuel Cuesta nor the names of its contributors may be
used to endorse or promote products derived from this software without specific
prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
POSSIBILITY OF SUCH DAMAGE.


**************************************************
Revision History / Change Log:

**************************************************
Notes:

*******************************************************************************/

package com.cuesta.web.tags;

import java.io.IOException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.jsp.tagext.*;
import javax.servlet.jsp.JspWriter;
import javax.servlet.jsp.JspException;

/**
 * BaseTag.java
 *
 * Created on 12 de marzo de 2007, 8:43
 * Prints the web application's context name, for base url purposes and absolut referencing of images, javascript files and resources
 *
 * @author  Manuel Camilo Cuesta
 *
 */
public class BaseTag extends TagSupport {
    

    public int doStartTag() throws JspException {
        JspWriter out = this.pageContext.getOut();
        
        HttpServletRequest request = (HttpServletRequest) pageContext.getRequest();
        try 
        {
            out.print( request.getContextPath() );
        } 
        catch (IOException ex) 
        {
            ex.printStackTrace();
        }
        
        return EVAL_PAGE;
    }
    
}
