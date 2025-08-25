// import { useState } from 'react';
// import { useNavigate } from 'react-router-dom';
// import { Button } from '@/components/ui/button';
// import { Input } from '@/components/ui/input';
// import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
// import { Label } from '@/components/ui/label';

// import { useToast } from '@/hooks/use-toast';
// import { initiateLogin } from '@/api';
// import { Users, Mail, Lock, Eye, EyeOff, Sparkles, Brain, Search, Target } from 'lucide-react';

// const Login = () => {
//   const [email, setEmail] = useState('');
//   const [password, setPassword] = useState('');
//   const [showPassword, setShowPassword] = useState(false);
//   const [isLoading, setIsLoading] = useState(false);
//   const navigate = useNavigate();
//   const { toast } = useToast();

//   const handleLogin = async (e: React.FormEvent) => {
//     e.preventDefault();
//     if (!email.trim() || !password.trim()) {
//       toast({
//         variant: 'destructive',
//         title: 'Error',
//         description: 'Please enter both email and password.',
//       });
//       return;
//     }

//     setIsLoading(true);
//     // Simulate email/password login
//     setTimeout(() => {
//       setIsLoading(false);
//       navigate('/dashboard');
//     }, 1500);
//   };

//   const handleMicrosoftLogin = async () => {
//     setIsLoading(true);
//     try {
//       const loginUrl = await initiateLogin();
//       console.log("Initiating Microsoft login, redirecting to:", loginUrl); // Debug log
//       window.location.href = loginUrl;
//     } catch (error) {
//       setIsLoading(false);
//       toast({
//         variant: 'destructive',
//         title: 'Error',
//         description: error instanceof Error ? error.message : 'Failed to initiate Microsoft login.',
//       });
//     }
//   };

//   const handleSocialLogin = (provider: string) => {
//     toast({
//       variant: 'destructive',
//       title: 'Not Implemented',
//       description: `${provider} login is not implemented yet.`,
//     });
//   };

//   return (
//     <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-purple-50 flex items-center justify-center p-4">
//       <div className="absolute inset-0 overflow-hidden">
//         <div className="absolute top-20 left-20 w-32 h-32 bg-blue-200/20 rounded-full blur-xl animate-float"></div>
//         <div className="absolute bottom-32 right-32 w-48 h-48 bg-purple-200/20 rounded-full blur-xl animate-float" style={{ animationDelay: '2s' }}></div>
//         <div className="absolute top-1/2 left-1/3 w-24 h-24 bg-indigo-200/20 rounded-full blur-xl animate-float" style={{ animationDelay: '4s' }}></div>
//       </div>

//       <div className="w-full max-w-6xl grid lg:grid-cols-2 gap-8 relative z-10">
//         <div className="hidden lg:flex flex-col justify-center space-y-8 px-8">
//           <div className="space-y-6">
//             <div className="flex items-center space-x-4">
//               <div className="w-16 h-16 bg-gradient-to-br from-blue-600 to-purple-600 rounded-2xl flex items-center justify-center animate-glow shadow-2xl">
//                 <Users className="w-8 h-8 text-white" />
//               </div>
//               <div>
//                 <h1 className="text-4xl font-bold gradient-text">QHub</h1>
//                 <p className="text-lg text-gray-600">Enterprise Candidate Search</p>
//               </div>
//             </div>
//             <div className="space-y-6">
//               <h2 className="text-3xl font-bold text-gray-800">
//                 Welcome to the Future of
//                 <span className="gradient-text"> AI-Powered Recruiting</span>
//               </h2>
//               <p className="text-lg text-gray-600 leading-relaxed">
//                 Transform your hiring process with intelligent candidate matching, 
//                 natural language search, and automated resume analysis.
//               </p>
//             </div>
//             <div className="grid grid-cols-1 gap-4">
//               <div className="flex items-center space-x-4 p-4 glass-card rounded-xl hover:scale-105 transition-all duration-300">
//                 <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center">
//                   <Brain className="w-6 h-6 text-blue-600" />
//                 </div>
//                 <div>
//                   <h3 className="font-semibold text-gray-800">AI-Powered Matching</h3>
//                   <p className="text-sm text-gray-600">Smart algorithms find perfect candidates</p>
//                 </div>
//               </div>
//               <div className="flex items-center space-x-4 p-4 glass-card rounded-xl hover:scale-105 transition-all duration-300">
//                 <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center">
//                   <Search className="w-6 h-6 text-purple-600" />
//                 </div>
//                 <div>
//                   <h3 className="font-semibold text-gray-800">Natural Language Search</h3>
//                   <p className="text-sm text-gray-600">Search candidates like you talk</p>
//                 </div>
//               </div>
//               <div className="flex items-center space-x-4 p-4 glass-card rounded-xl hover:scale-105 transition-all duration-300">
//                 <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center">
//                   <Target className="w-6 h-6 text-green-600" />
//                 </div>
//                 <div>
//                   <h3 className="font-semibold text-gray-800">Precision Filtering</h3>
//                   <p className="text-sm text-gray-600">Advanced filters for exact matches</p>
//                 </div>
//               </div>
//             </div>
//           </div>
//         </div>
//         <div className="flex items-center justify-center">
//           <Card className="w-full max-w-md glass-card border-0 shadow-2xl animate-scale-in">
//             <CardHeader className="text-center space-y-4 pb-8">
//               <div className="lg:hidden flex items-center justify-center space-x-3 mb-4">
//                 <div className="w-12 h-12 bg-gradient-to-br from-blue-600 to-purple-600 rounded-xl flex items-center justify-center animate-glow">
//                   <Users className="w-6 h-6 text-white" />
//                 </div>
//                 <div>
//                   <h1 className="text-2xl font-bold gradient-text">QHub</h1>
//                 </div>
//               </div>
//               <CardTitle className="text-2xl font-bold text-gray-800">Welcome Back</CardTitle>
//               <p className="text-gray-600">Sign in to your QHub account</p>
//             </CardHeader>
//             <CardContent className="space-y-6">
//               <form onSubmit={handleLogin} className="space-y-4">
//                 <div className="space-y-2">
//                   <Label htmlFor="email" className="text-sm font-medium text-gray-700">
//                     Email Address
//                   </Label>
//                   <div className="relative">
//                     <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
//                     <Input
//                       id="email"
//                       type="email"
//                       placeholder="Enter your email"
//                       value={email}
//                       onChange={(e) => setEmail(e.target.value)}
//                       className="pl-10 h-12 glass border-gray-200 focus:border-blue-400 focus:ring-blue-400"
//                       disabled={isLoading}
//                     />
//                   </div>
//                 </div>
//                 <div className="space-y-2">
//                   <Label htmlFor="password" className="text-sm font-medium text-gray-700">
//                     Password
//                   </Label>
//                   <div className="relative">
//                     <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
//                     <Input
//                       id="password"
//                       type={showPassword ? 'text' : 'password'}
//                       placeholder="Enter your password"
//                       value={password}
//                       onChange={(e) => setPassword(e.target.value)}
//                       className="pl-10 pr-10 h-12 glass border-gray-200 focus:border-blue-400 focus:ring-blue-400"
//                       disabled={isLoading}
//                     />
//                     <button
//                       type="button"
//                       onClick={() => setShowPassword(!showPassword)}
//                       className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600 transition-colors"
//                       disabled={isLoading}
//                     >
//                       {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
//                     </button>
//                   </div>
//                 </div>
//                 <div className="flex items-center justify-between text-sm">
//                   <label className="flex items-center space-x-2 cursor-pointer">
//                     <input type="checkbox" className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" />
//                     <span className="text-gray-600">Remember me</span>
//                   </label>
//                   <a href="#" className="text-blue-600 hover:text-blue-800 font-medium transition-colors">
//                     Forgot password?
//                   </a>
//                 </div>
//                 <Button
//                   type="submit"
//                   disabled={isLoading || !email.trim() || !password.trim()}
//                   className="w-full h-12 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white font-semibold rounded-lg transition-all duration-300 hover:scale-105 disabled:hover:scale-100"
//                 >
//                   {isLoading ? (
//                     <div className="flex items-center space-x-2">
//                       <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
//                       <span>Signing in...</span>
//                     </div>
//                   ) : (
//                     <div className="flex items-center space-x-2">
//                       <Sparkles className="w-4 h-4" />
//                       <span>Sign In</span>
//                     </div>
//                   )}
//                 </Button>
//               </form>
//               <div className="relative">
//                 <div className="absolute inset-0 flex items-center">
//                   <div className="w-full border-t border-gray-200"></div>
//                 </div>
//                 <div className="relative flex justify-center text-sm">
//                   <span className="px-4 bg-white text-gray-500">Or continue with</span>
//                 </div>
//               </div>
//               <div className="grid grid-cols-3 gap-4">
//                 <Button
//                   type="button"
//                   variant="outline"
//                   onClick={() => handleMicrosoftLogin()}
//                   disabled={isLoading}
//                   className="h-12 glass border-gray-200 hover:bg-gray-50 transition-all duration-300 hover:scale-105"
//                 >
//                   <svg className="w-5 h-5 mr-2" viewBox="0 0 24 24" fill="none">
//                     <path fill="#F25022" d="M2 3h9v9H2V3z"/>
//                     <path fill="#7FBA00" d="M2 13h9v9H2v-9z"/>
//                     <path fill="#00A4EF" d="M13 3h9v9h-9V3z"/>
//                     <path fill="#FFB900" d="M13 13h9v9h-9v-9z"/>
//                   </svg>
//                   Microsoft
//                 </Button>
//                 <Button
//                   type="button"
//                   variant="outline"
//                   onClick={() => handleSocialLogin('Google')}
//                   disabled={isLoading}
//                   className="h-12 glass border-gray-200 hover:bg-gray-50 transition-all duration-300 hover:scale-105"
//                 >
//                   <svg className="w-5 h-5 mr-2" viewBox="0 0 24 24">
//                     <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.20-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
//                     <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
//                     <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
//                     <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
//                   </svg>
//                   Google
//                 </Button>
//                 <Button
//                   type="button"
//                   variant="outline"
//                   onClick={() => handleSocialLogin('LinkedIn')}
//                   disabled={isLoading}
//                   className="h-12 glass border-gray-200 hover:bg-gray-50 transition-all duration-300 hover:scale-105"
//                 >
//                   <svg className="w-5 h-5 mr-2" fill="#0A66C2" viewBox="0 0 24 24">
//                     <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
//                   </svg>
//                   LinkedIn
//                 </Button>
//               </div>
//               <div className="text-center text-sm text-gray-600">
//                 Don't have an account?{' '}
//                 <a href="#" className="text-blue-600 hover:text-blue-800 font-medium transition-colors">
//                   Sign up for free
//                 </a>
//               </div>
//             </CardContent>
//           </Card>
//         </div>
//       </div>
//     </div>
//   );
// };

// export default Login;











import { useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Label } from '@/components/ui/label';
import { useToast } from '@/hooks/use-toast';
import { initiateLogin, initiateGoogleLogin } from '@/api/api';
import { Users, Mail, Lock, Eye, EyeOff, Sparkles, Brain, Search, Target } from 'lucide-react';

const Login = () => {
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [isLoading, setIsLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);
  const navigate = useNavigate();
  const { toast } = useToast();

  const handleLogin = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!email.trim() || !password.trim()) {
      toast({
        variant: 'destructive',
        title: 'Error',
        description: 'Please enter both email and password.',
      });
      return;
    }

    setIsLoading(true);
    // Simulate email/password login
    setTimeout(() => {
      setIsLoading(false);
      navigate('/dashboard');
    }, 1500);
  };

  const handleMicrosoftLogin = async () => {
    setIsLoading(true);
    try {
      const loginUrl = initiateLogin();
      console.log("Initiating Microsoft login, redirecting to:", loginUrl);
      window.location.href = loginUrl;
    } catch (error) {
      setIsLoading(false);
      toast({
        variant: 'destructive',
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to initiate Microsoft login.',
      });
    }
  };

  const handleGoogleLogin = async () => {
    setGoogleLoading(true);
    try {
      const loginUrl = initiateGoogleLogin();
      console.log("Initiating Google login, redirecting to:", loginUrl);
      window.location.href = loginUrl;
    } catch (error) {
      setGoogleLoading(false);
      toast({
        variant: 'destructive',
        title: 'Error',
        description: error instanceof Error ? error.message : 'Failed to initiate Google login.',
      });
    }
  };

  const handleSocialLogin = (provider: string) => {
    if (provider === 'LinkedIn') {
      toast({
        variant: 'destructive',
        title: 'Not Implemented',
        description: `${provider} login is not implemented yet.`,
      });
    }
  };

  return (
    <div className="min-h-screen bg-gradient-to-br from-slate-50 via-blue-50 to-purple-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 overflow-hidden">
        <div className="absolute top-20 left-20 w-32 h-32 bg-blue-200/20 rounded-full blur-xl animate-float"></div>
        <div className="absolute bottom-32 right-32 w-48 h-48 bg-purple-200/20 rounded-full blur-xl animate-float" style={{ animationDelay: '2s' }}></div>
        <div className="absolute top-1/2 left-1/3 w-24 h-24 bg-indigo-200/20 rounded-full blur-xl animate-float" style={{ animationDelay: '4s' }}></div>
      </div>

      <div className="w-full max-w-6xl grid lg:grid-cols-2 gap-8 relative z-10">
        <div className="hidden lg:flex flex-col justify-center space-y-8 px-8">
          <div className="space-y-6">
            <div className="flex items-center space-x-4">
              <div className="w-16 h-16 bg-gradient-to-br from-blue-600 to-purple-600 rounded-2xl flex items-center justify-center animate-glow shadow-2xl">
                <Users className="w-8 h-8 text-white" />
              </div>
              <div>
                <h1 className="text-4xl font-bold gradient-text">QHub</h1>
                <p className="text-lg text-gray-600">Enterprise Candidate Search</p>
              </div>
            </div>
            <div className="space-y-6">
              <h2 className="text-3xl font-bold text-gray-800">
                Welcome to the Future of
                <span className="gradient-text"> AI-Powered Recruiting</span>
              </h2>
              <p className="text-lg text-gray-600 leading-relaxed">
                Transform your hiring process with intelligent candidate matching, 
                natural language search, and automated resume analysis.
              </p>
            </div>
            <div className="grid grid-cols-1 gap-4">
              <div className="flex items-center space-x-4 p-4 glass-card rounded-xl hover:scale-105 transition-all duration-300">
                <div className="w-12 h-12 bg-blue-100 rounded-lg flex items-center justify-center">
                  <Brain className="w-6 h-6 text-blue-600" />
                </div>
                <div>
                  <h3 className="font-semibold text-gray-800">AI-Powered Matching</h3>
                  <p className="text-sm text-gray-600">Smart algorithms find perfect candidates</p>
                </div>
              </div>
              <div className="flex items-center space-x-4 p-4 glass-card rounded-xl hover:scale-105 transition-all duration-300">
                <div className="w-12 h-12 bg-purple-100 rounded-lg flex items-center justify-center">
                  <Search className="w-6 h-6 text-purple-600" />
                </div>
                <div>
                  <h3 className="font-semibold text-gray-800">Natural Language Search</h3>
                  <p className="text-sm text-gray-600">Search candidates like you talk</p>
                </div>
              </div>
              <div className="flex items-center space-x-4 p-4 glass-card rounded-xl hover:scale-105 transition-all duration-300">
                <div className="w-12 h-12 bg-green-100 rounded-lg flex items-center justify-center">
                  <Target className="w-6 h-6 text-green-600" />
                </div>
                <div>
                  <h3 className="font-semibold text-gray-800">Precision Filtering</h3>
                  <p className="text-sm text-gray-600">Advanced filters for exact matches</p>
                </div>
              </div>
            </div>
          </div>
        </div>
        <div className="flex items-center justify-center">
          <Card className="w-full max-w-md glass-card border-0 shadow-2xl animate-scale-in">
            <CardHeader className="text-center space-y-4 pb-8">
              <div className="lg:hidden flex items-center justify-center space-x-3 mb-4">
                <div className="w-12 h-12 bg-gradient-to-br from-blue-600 to-purple-600 rounded-xl flex items-center justify-center animate-glow">
                  <Users className="w-6 h-6 text-white" />
                </div>
                <div>
                  <h1 className="text-2xl font-bold gradient-text">QHub</h1>
                </div>
              </div>
              <CardTitle className="text-2xl font-bold text-gray-800">Welcome Back</CardTitle>
              <p className="text-gray-600">Sign in to your QHub account</p>
            </CardHeader>
            <CardContent className="space-y-6">
              <form onSubmit={handleLogin} className="space-y-4">
                <div className="space-y-2">
                  <Label htmlFor="email" className="text-sm font-medium text-gray-700">
                    Email Address
                  </Label>
                  <div className="relative">
                    <Mail className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                    <Input
                      id="email"
                      type="email"
                      placeholder="Enter your email"
                      value={email}
                      onChange={(e) => setEmail(e.target.value)}
                      className="pl-10 h-12 glass border-gray-200 focus:border-blue-400 focus:ring-blue-400"
                      disabled={isLoading || googleLoading}
                    />
                  </div>
                </div>
                <div className="space-y-2">
                  <Label htmlFor="password" className="text-sm font-medium text-gray-700">
                    Password
                  </Label>
                  <div className="relative">
                    <Lock className="absolute left-3 top-1/2 transform -translate-y-1/2 text-gray-400 w-4 h-4" />
                    <Input
                      id="password"
                      type={showPassword ? 'text' : 'password'}
                      placeholder="Enter your password"
                      value={password}
                      onChange={(e) => setPassword(e.target.value)}
                      className="pl-10 pr-10 h-12 glass border-gray-200 focus:border-blue-400 focus:ring-blue-400"
                      disabled={isLoading || googleLoading}
                    />
                    <button
                      type="button"
                      onClick={() => setShowPassword(!showPassword)}
                      className="absolute right-3 top-1/2 transform -translate-y-1/2 text-gray-400 hover:text-gray-600 transition-colors"
                      disabled={isLoading || googleLoading}
                    >
                      {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
                <div className="flex items-center justify-between text-sm">
                  <label className="flex items-center space-x-2 cursor-pointer">
                    <input 
                      type="checkbox" 
                      className="rounded border-gray-300 text-blue-600 focus:ring-blue-500" 
                      disabled={isLoading || googleLoading}
                    />
                    <span className="text-gray-600">Remember me</span>
                  </label>
                  <a href="#" className="text-blue-600 hover:text-blue-800 font-medium transition-colors">
                    Forgot password?
                  </a>
                </div>
                <Button
                  type="submit"
                  disabled={isLoading || googleLoading || !email.trim() || !password.trim()}
                  className="w-full h-12 bg-gradient-to-r from-blue-600 to-purple-600 hover:from-blue-700 hover:to-purple-700 text-white font-semibold rounded-lg transition-all duration-300 hover:scale-105 disabled:hover:scale-100"
                >
                  {isLoading ? (
                    <div className="flex items-center space-x-2">
                      <div className="w-4 h-4 border-2 border-white border-t-transparent rounded-full animate-spin"></div>
                      <span>Signing in...</span>
                    </div>
                  ) : (
                    <div className="flex items-center space-x-2">
                      <Sparkles className="w-4 h-4" />
                      <span>Sign In</span>
                    </div>
                  )}
                </Button>
              </form>
              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-gray-200"></div>
                </div>
                <div className="relative flex justify-center text-sm">
                  <span className="px-4 bg-white text-gray-500">Or continue with</span>
                </div>
              </div>
              <div className="grid grid-cols-3 gap-4">
                <Button
                  type="button"
                  variant="outline"
                  onClick={handleMicrosoftLogin}
                  disabled={isLoading || googleLoading}
                  className="h-12 glass border-gray-200 hover:bg-gray-50 transition-all duration-300 hover:scale-105"
                >
                  <svg className="w-5 h-5 mr-2" viewBox="0 0 24 24" fill="none">
                    <path fill="#F25022" d="M2 3h9v9H2V3z"/>
                    <path fill="#7FBA00" d="M2 13h9v9H2v-9z"/>
                    <path fill="#00A4EF" d="M13 3h9v9h-9V3z"/>
                    <path fill="#FFB900" d="M13 13h9v9h-9v-9z"/>
                  </svg>
                  Microsoft
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={handleGoogleLogin}
                  disabled={isLoading || googleLoading}
                  className="h-12 glass border-gray-200 hover:bg-gray-50 transition-all duration-300 hover:scale-105"
                >
                  {googleLoading ? (
                    <div className="flex items-center justify-center">
                      <div className="w-5 h-5 border-2 border-blue-500 border-t-transparent rounded-full animate-spin mr-2"></div>
                      <span>Redirecting...</span>
                    </div>
                  ) : (
                    <>
                      <svg className="w-5 h-5 mr-2" viewBox="0 0 24 24">
                        <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.20-2.25H12v4.26h5.92c-.26 1.37-1.04 2.53-2.21 3.31v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.09z"/>
                        <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
                        <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
                        <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
                      </svg>
                      Google
                    </>
                  )}
                </Button>
                <Button
                  type="button"
                  variant="outline"
                  onClick={() => handleSocialLogin('LinkedIn')}
                  disabled={isLoading || googleLoading}
                  className="h-12 glass border-gray-200 hover:bg-gray-50 transition-all duration-300 hover:scale-105"
                >
                  <svg className="w-5 h-5 mr-2" fill="#0A66C2" viewBox="0 0 24 24">
                    <path d="M20.447 20.452h-3.554v-5.569c0-1.328-.027-3.037-1.852-3.037-1.853 0-2.136 1.445-2.136 2.939v5.667H9.351V9h3.414v1.561h.046c.477-.9 1.637-1.85 3.37-1.85 3.601 0 4.267 2.37 4.267 5.455v6.286zM5.337 7.433c-1.144 0-2.063-.926-2.063-2.065 0-1.138.92-2.063 2.063-2.063 1.14 0 2.064.925 2.064 2.063 0 1.139-.925 2.065-2.064 2.065zm1.782 13.019H3.555V9h3.564v11.452zM22.225 0H1.771C.792 0 0 .774 0 1.729v20.542C0 23.227.792 24 1.771 24h20.451C23.2 24 24 23.227 24 22.271V1.729C24 .774 23.2 0 22.222 0h.003z"/>
                  </svg>
                  LinkedIn
                </Button>
              </div>
              <div className="text-center text-sm text-gray-600">
                Don't have an account?{' '}
                <a href="#" className="text-blue-600 hover:text-blue-800 font-medium transition-colors">
                  Sign up for free
                </a>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  );
};

export default Login;