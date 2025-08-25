// import axios, { AxiosResponse } from 'axios';

// const API_BASE_URL = 'http://localhost:8000';

// export interface Candidate {
//   id: string;
//   name: string;
//   date_of_birth: string;
//   skills: string[];
//   personal_information: {
//     first_name: string;
//     last_name: string;
//     email: string;
//     phone_number: string;
//   };
//   professional_information: {
//     position: string;
//     current_last_company: string;
//     location: string;
//     current_ctc: number;
//     expected_ctc: number;
//     total_experience: number;
//   };
//   professional_summary: string;
//   resume_uploaded: string;
//   projects: { title: string; description: string }[];
//   certifications: string[];
// }

// export interface AddResumesResponse {
//   message: string;
//   results: string[];
//   errors: string[];
//   parsed_resumes: Candidate[];
// }

// export interface SearchResponse {
//   response: string;
//   id: string;
//   match: Candidate[];
//   metadata: {
//     query_plan: any;
//     retrieved_results_count: number;
//     confidence: number;
//   };
// }

// export interface AllCandidatesResponse {
//   candidates: Candidate[];
// }

// const apiClient = axios.create({
//   baseURL: API_BASE_URL,
//   headers: {
//     'Content-Type': 'application/json',
//   },
// });

// // Get all candidates
// export const getAllCandidates = async (): Promise<AllCandidatesResponse> => {
//   try {
//     const response: AxiosResponse<AllCandidatesResponse> = await apiClient.get('/candidates');
//     return response.data;
//   } catch (error) {
//     console.error('Get all candidates error:', error);
//     throw new Error('Failed to fetch all candidates. Please try again later.');
//   }
// };

// // Ingest candidates with optional files
// export const ingestCandidates = async (candidates: Candidate[], files: File[]): Promise<AddResumesResponse> => {
//   try {
//     const formData = new FormData();
//     formData.append('employees', JSON.stringify(candidates));
//     files.forEach((file) => {
//       formData.append('files', file);
//     });

//     const response: AxiosResponse<AddResumesResponse> = await apiClient.post('/ingest', formData, {
//       headers: {
//         'Content-Type': 'multipart/form-data',
//       },
//     });
//     return response.data;
//   } catch (error) {
//     console.error('Ingest candidates error:', error);
//     throw new Error('Failed to ingest candidates. Please try again later.');
//   }
// };

// // Upload resumes
// export const uploadResumes = async (files: File[]): Promise<AddResumesResponse> => {
//   try {
//     const formData = new FormData();
//     files.forEach((file) => {
//       formData.append('files', file);
//     });

//     const response: AxiosResponse<AddResumesResponse> = await apiClient.post('/add-resumes', formData, {
//       headers: {
//         'Content-Type': 'multipart/form-data',
//       },
//     });
//     return response.data;
//   } catch (error) {
//     console.error('Upload resumes error:', error);
//     throw new Error('Failed to upload resumes. Please try again later.');
//   }
// };

// // Search candidates
// export const searchCandidates = async (query: string, limit: number = 1000, file?: File): Promise<SearchResponse> => {


//   try {
//     const response: AxiosResponse<SearchResponse> = await apiClient.post('/search', { query, limit });
//     return response.data;
//   } catch (error) {
//     console.error('Search error:', error);
//     throw new Error('Failed to fetch candidates. Please try again later.');
//   }
// };

// // Fetch candidate by ID
// export const getCandidateById = async (id: string): Promise<Candidate> => {
//   try {
//     const response: AxiosResponse<Candidate> = await apiClient.get(`/candidate/${id}`);
//     return response.data;
//   } catch (error) {
//     console.error('Fetch candidate error:', error);
//     throw new Error('Failed to fetch candidate details. Please try again later.');
//   }
// };







import axios from 'axios';

const API_BASE_URL = 'http://localhost:8000'; // Update if your backend runs on a different URL/port
const NODE_API_BASE_URL = 'http://localhost:4000';

// Interface for User data from /users endpoint
export interface User {
  user_id: string;
  display_name?: string;
  email: string;
  given_name?: string;
  surname?: string;
  job_title?: string;
  office_location?: string;
  working_hours?: {
    start_time: string;
    end_time: string;
  };
  timezone?: string;
}

export interface LoginResponse {
  login_url: string;
}

// Interface for PanelSelection payload
export interface PanelSelection {
  user_ids: string[];
  created_by: string; // Added created_by field
}

// Interface for PanelSelection response
export interface PanelSelectionResponse {
  session_id: string;
}

// Interface for InterviewDetails payload
export interface InterviewDetails {
  title: string;
  description: string;
  duration: number;
  date: string;
  preferred_timezone: string;
  location: string;
}

// Interface for InterviewDetails response
export interface InterviewDetailsResponse {
  message: string;
}

// Interface for TimeSlot in availability response
export interface TimeSlot {
  start: string; // e.g., "11:30 AM"
  end: string; // e.g., "12:30 PM"
  date: string; // e.g., "2025-08-28"
}

// Interface for Availability response
export interface AvailabilityResponse {
  slots: TimeSlot[];
  metadata: {
    total_slots: number;
    date: string;
    duration_minutes: number;
    timezone: string;
    panel_members: number;
    note?: string;
  };
}

// Interface for API error response
export interface ApiError {
  error: string;
}

// Configure axios instance
const apiClient = axios.create({
  baseURL: API_BASE_URL,
  headers: {
    'Content-Type': 'application/json',
  },
});

// Initiate Microsoft login
export const initiateLogin = (): string => {
  return 'http://localhost:8000/login'; // Directly return the backend login endpoint
};

// Initiate Google login
export const initiateGoogleLogin = (): string => {
  return 'http://localhost:8000/google-login';
};

// Fetch all users
export const fetchUsers = async (): Promise<User[]> => {
  try {
    const response = await apiClient.get<{ users: User[] }>('/users');
    return response.data.users;
  } catch (error) {
    if (axios.isAxiosError(error) && error.response) {
      throw new Error((error.response.data as ApiError).error || 'Failed to fetch users');
    }
    throw new Error('Network error while fetching users');
  }
};

// Save panel selection
export const savePanelSelection = async (userIds: string[], createdBy: string): Promise<string> => {
  try {
    const response = await apiClient.post<PanelSelectionResponse>('/panel-selection', {
      user_ids: userIds,
      created_by: createdBy, // Include created_by in the request body
    });
    return response.data.session_id;
  } catch (error) {
    if (axios.isAxiosError(error) && error.response) {
      throw new Error((error.response.data as ApiError).error || 'Failed to save panel selection');
    }
    throw new Error('Network error while saving panel selection');
  }
};

// Save interview details
export const saveInterviewDetails = async (sessionId: string, details: InterviewDetails): Promise<string> => {
  try {
    const response = await apiClient.post<InterviewDetailsResponse>(`/interview-details/${sessionId}`, details);
    return response.data.message;
  } catch (error) {
    if (axios.isAxiosError(error) && error.response) {
      throw new Error((error.response.data as ApiError).error || 'Failed to save interview details');
    }
    throw new Error('Network error while saving interview details');
  }
};

// Fetch available slots (working hours)
export const fetchAvailableSlots = async (sessionId: string): Promise<AvailabilityResponse> => {
  try {
    const response = await apiClient.get<AvailabilityResponse>(`/available-slots/${sessionId}`);
    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error) && error.response) {
      throw new Error((error.response.data as ApiError).error || 'Failed to fetch available slots');
    }
    throw new Error('Network error while fetching available slots');
  }
};

// Fetch all available slots (all hours)
export const fetchAllAvailableSlots = async (sessionId: string): Promise<AvailabilityResponse> => {
  try {
    const response = await apiClient.get<AvailabilityResponse>(`/all-available-slots/${sessionId}`);
    return response.data;
  } catch (error) {
    if (axios.isAxiosError(error) && error.response) {
      throw new Error((error.response.data as ApiError).error || 'Failed to fetch all available slots');
    }
    throw new Error('Network error while fetching all available slots');
  }
};

// Interface for Candidate data from /profile endpoint
export interface ApiCandidate {
  name: string | null;
  total_experience: number | null;
  email: string | null;
  linkedin_url: string | null;
  github_url: string | null;
  projects: {
    title: string;
    description: string;
    skills_tools: string[];
    impact: string | null;
    start_date: string | null;
    end_date: string | null;
  }[];
  work_history: {
    company: string;
    designation: string;
    description: string;
    start_date: string;
    end_date: string | null;
  }[];
  primary_skills: { [category: string]: string[] };
  secondary_skills: { [category: string]: string[] };
  course: {
    institution: string;
    domain: string;
    level: string;
  }[];
  certifications: string[];
  education: {
    institution: string | null;
    degree: string;
    domain: string;
  }[];
  profile_id: string;
  file_name: string;
  processed_at: string;
}

// Interface for /profile API response
export interface ProfileResponse {
  message: string;
  count: number;
  body: ApiCandidate[];
}

// Fetch all candidate profiles
export const fetchAllProfiles = async (): Promise<ApiCandidate[]> => {
  try {
    const response = await apiClient.get<ProfileResponse>('/profile');
    return response.data.body;
  } catch (error) {
    if (axios.isAxiosError(error) && error.response) {
      throw new Error((error.response.data as ApiError).error || 'Failed to fetch profiles');
    }
    throw new Error('Network error while fetching profiles');
  }
};

export interface SingleProfileResponse {
  message: string;
  body: ApiCandidate;
}

// Fetch a single candidate profile by profile_id
export const fetchProfileById = async (profileId: string): Promise<ApiCandidate> => {
  try {
    const response = await apiClient.get<SingleProfileResponse>(`/profile/${profileId}`);
    return response.data.body;
  } catch (error) {
    if (axios.isAxiosError(error) && error.response) {
      throw new Error((error.response.data as ApiError).error || 'Failed to fetch profile');
    }
    throw new Error('Network error while fetching profile');
  }
};

interface SkillMatchDetails {
  matched_skills: string[];
  missing_skills: string[];
  total_matched: number;
  total_required: number;
  match_percentage: number;
}

interface AggregatedScore {
  resume_name: string;
  resume_id: string;
  aggregated_score: number;
  score_breakdown: {
    primary_vs_primary: number;
    primary_vs_secondary: number;
    secondary_vs_primary: number;
    secondary_vs_secondary: number;
  };
  primary_vs_primary: SkillMatchDetails;
  secondary_vs_secondary: SkillMatchDetails;
  rank: number;
}

interface MatchingResponse {
  jd_text: string;
  job_title: string;
  total_resumes_processed: number;
  matching_results: AggregatedScore[];
  timestamp: string;
  execution_time_ms: number;
}

const BASE_URL = "http://localhost:8000"; // Update with your backend URL

const fetchWithToken = async (url: string, options: RequestInit = {}) => {
  const sessionId = localStorage.getItem("session_id");
  const headers = new Headers(options.headers || {});
  
  if (sessionId) {
    headers.append("Authorization", `Bearer ${sessionId}`);
  }
  
  try {
    const response = await fetch(url, {
      ...options,
      headers,
    });
    
    if (!response.ok) {
      const errorData = await response.json();
      throw new Error(errorData.detail || `HTTP error! status: ${response.status}`);
    }
    
    return await response.json();
  } catch (error) {
    console.error(`Error fetching ${url}:`, error);
    throw error;
  }
};

export const fetchMatchingResumes = async (formData: FormData): Promise<MatchingResponse> => {
  return fetchWithToken(`${BASE_URL}/find-match`, {
    method: "POST",
    body: formData,
  });
};

export type { MatchingResponse, AggregatedScore, SkillMatchDetails };

interface ScheduleEventRequest {
  slot: {
    start: string;
    end: string;
  };
  mail_template: {
    subject: string;
    body: string;
  };
  candidate_email: string | null;
}

interface ScheduleEventResponse {
  message?: string;
  error?: string;
}

const scheduleEvent = async (sessionId: string, request: ScheduleEventRequest): Promise<ScheduleEventResponse> => {
  return fetchWithToken(`${BASE_URL}/schedule-event/${sessionId}`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
    },
    body: JSON.stringify(request),
  });
};

export type { ScheduleEventRequest, ScheduleEventResponse };
export { scheduleEvent };

interface EventTrackerResponse {
  status?: string;
  candidate?: {
    name: string;
    email: string;
  };
  position?: string;
  scheduled_time?: {
    date: string;
    start_time: string;
    duration: number;
  };
  virtual?: boolean;
  candidate_response?: {
    name: string;
    email: string;
    response: string;
    response_time: string;
  };
  panel_response_status?: {
    summary: {
      accepted: number;
      declined: number;
      tentative: number;
      pending: number;
    };
    responses: Array<{
      name: string;
      email: string;
      role: string | null;
      response: string;
      response_time: string;
    }>;
  };
  error?: string;
}

const trackEvent = async (sessionId: string): Promise<EventTrackerResponse> => {
  return fetchWithToken(`${BASE_URL}/event-tracker/${sessionId}`, {
    method: "GET",
    headers: {
      "Content-Type": "application/json",
    },
  });
};

interface UploadResumeResponse {
  message: string;
  uploaded_files_count?: number;
  status?: string;
  save_errors?: Array<{
    filename: string;
    error: string;
  }>;
  errors?: Array<{
    filename: string;
    error: string;
  }>;
  valid_files_count?: number;
}

const uploadResumes = async (files: File[]): Promise<UploadResumeResponse> => {
  const formData = new FormData();
  files.forEach((file) => {
    formData.append('files', file);
  });

  return fetchWithToken(`${BASE_URL}/upload-resumes`, {
    method: 'POST',
    body: formData,
  });
};

interface ImportExcelResponse {
  success?: boolean;
  message?: string;
  status?: string;
  data?: any;
  error?: { message: string; details?: string };
}

const importExcel = async (file: File): Promise<ImportExcelResponse> => {
  const formData = new FormData();
  formData.append('excelFile', file);

  const response = await fetch(`${NODE_API_BASE_URL}/api/profiles/import-excel`, {
    method: 'POST',
    body: formData,
  });

  const responseData = await response.json().catch(() => ({}));
  console.log('importExcel: Response:', responseData);

  if (!response.ok) {
    console.log('importExcel: Error response:', responseData);
    throw new Error(`HTTP error! status: ${response.status}, message: ${responseData.error?.message || 'Unknown error'}`);
  }

  return responseData;
};

export type { EventTrackerResponse, UploadResumeResponse, ImportExcelResponse };
export { trackEvent, uploadResumes, importExcel };

interface SchedulerResponse {
  interviews: {
    session_id: string;
    candidate: {
      email: string;
      name: string;
      recent_designation: string;
      profile_id: string;
    };
    event_start_time: string;
    panel_emails: string[];
  }[];
  statistics: {
    total: number;
    scheduled: number;
    pending: number;
    completed: number;
  };
  error?: string;
}

const fetchSchedulerData = async (): Promise<SchedulerResponse> => {
  const response = await fetch(`${API_BASE_URL}/scheduler`, {
    method: 'GET',
  });

  const responseData = await response.json().catch(() => ({}));
  console.log('fetchSchedulerData: Response:', responseData);

  if (!response.ok) {
    console.log('fetchSchedulerData: Error response:', responseData);
    throw new Error(`HTTP error! status: ${response.status}, message: ${responseData.error || 'Unknown error'}`);
  }

  return responseData;
};

export type { SchedulerResponse };
export { fetchSchedulerData };

interface EventUpdateRequest {
  remove_emails: string[];
  add_emails: string[];
}

interface EventUpdateResponse {
  success?: boolean;
  error?: string;
}

const updateEvent = async (sessionId: string, removeEmails: string[], addEmails: string[]): Promise<EventUpdateResponse> => {
  const authSessionId = localStorage.getItem("session_id");
  if (!authSessionId) {
    throw new Error("No session ID found");
  }

  const response = await fetch(`http://localhost:8000/event-update/${sessionId}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${authSessionId}`,
    },
    body: JSON.stringify({
      remove_emails: removeEmails,
      add_emails: addEmails,
    }),
  });

  const responseData = await response.json().catch(() => ({}));
  console.log('updateEvent: Response:', responseData);

  if (!response.ok) {
    console.log('updateEvent: Error response:', responseData);
    throw new Error(`HTTP error! status: ${response.status}, message: ${responseData.error || 'Unknown error'}`);
  }

  return responseData;
};

export type { EventUpdateRequest, EventUpdateResponse };
export { updateEvent };