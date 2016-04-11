using NBitcoin;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace ProgrammingBitcoinFunding
{
    public static class ScriptExtensions
    {
        public class State
        {
            public Stack<bool> vfExec;
            public List<Op> executionPath;
            public long position;
            public Op op;
        }
        public static Script[] Decompose(this Script script)
        {
            List<Script> scripts = new List<Script>();

            var reader = script.CreateReader();
            var vfExec = new Stack<bool>();
            List<Op> executionPath = new List<Op>();

            Stack<State> states = new Stack<State>();

            Op op;
            while((op = reader.Read()) != null || states.Count != 0)
            {
                bool statePopped = false;
                if(op == null)
                {
                    scripts.Add(new Script(executionPath.ToArray()));
                    var state = states.Pop();
                    vfExec = state.vfExec;
                    op = state.op;
                    executionPath = state.executionPath;
                    reader.Inner.Position = state.position;
                    statePopped = true;
                }
                bool fExec = vfExec.All(o => o);
                if(fExec || (OpcodeType.OP_IF <= op.Code && op.Code <= OpcodeType.OP_ENDIF))
                {
                    switch(op.Code)
                    {
                        case OpcodeType.OP_IF:
                        case OpcodeType.OP_NOTIF:
                            {
                                var bValue = !statePopped;
                                if(fExec)
                                {
                                    if(!statePopped)
                                    {
                                        State state = new State();
                                        state.op = op;
                                        state.executionPath = executionPath.ToList();
                                        state.position = reader.Inner.Position;
                                        state.vfExec = Clone(vfExec);
                                        states.Push(state);
                                    }
                                    if(bValue)
                                        executionPath.Add(OpcodeType.OP_VERIFY);
                                    else
                                    {
                                        executionPath.Add(OpcodeType.OP_NOT);
                                        executionPath.Add(OpcodeType.OP_VERIFY);
                                    }
                                }
                                if(op.Code == OpcodeType.OP_NOTIF)
                                    bValue = !bValue;
                                vfExec.Push(bValue);
                                break;
                            }
                        case OpcodeType.OP_ELSE:
                            {
                                if(vfExec.Count != 0)
                                {
                                    var v = vfExec.Pop();
                                    vfExec.Push(!v);
                                }
                                break;
                            }
                        case OpcodeType.OP_ENDIF:
                            {
                                if(vfExec.Count != 0)
                                {
                                    vfExec.Pop();
                                }
                                break;
                            }
                        default:
                            executionPath.Add(op);
                            break;
                    }
                }
            }
            if(executionPath.Count > 0)
                scripts.Add(new Script(executionPath.ToArray()));
            return scripts.ToArray();
        }

        private static Stack<T> Clone<T>(Stack<T> stack)
        {
            return new Stack<T>(stack.Reverse());
        }
    }
}
